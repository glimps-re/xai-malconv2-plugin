import io
from pathlib import Path

import numpy as np
from elftools.elf.elffile import ELFFile
import pefile
import lief
import torch
from captum.attr import DeepLift

from malconv2.MalConvGCT_nocat_Inf import MalConvGCT, Extracted_MLP


HEATMAP_LENGTH = 256


class MalConv2ModelError(Exception):
    """MalConv2 custom exception."""

    def __init__(self, message):
        self.message = message
        super().__init__(message)

    def to_dict(self):
        """Return dict form"""
        return {"message": self.message}


def get_exec_sections_elf(file_path: str):
    """Export executable sections of the provided ELF file."""
    with open(file_path, "rb") as fobj:
        file_data = fobj.read()
        # Create a file-like object from the buffered ELF data
        elf_file_from_mem = io.BytesIO(file_data)
        elf_file = ELFFile(elf_file_from_mem)
        exec_sections, raw_bytes = [], []
        for section in elf_file.iter_sections():
            if (section["sh_flags"] & 0x4) == 0x4:
                try:
                    name = section.Name.decode().rstrip("\x00")
                    name = name[:10]
                except Exception as _err:
                    name = "ERROR"
                exec_sections.append(
                    (
                        name,
                        section["sh_offset"],
                        section["sh_size"],
                        section["sh_addr"],
                        section["sh_size"],
                    )
                )
                fobj.seek(section["sh_offset"])
                raw_bytes += fobj.read(section["sh_size"])
        return raw_bytes, exec_sections


def get_exec_sections_pe(file_path: str):
    """Export executable sections of the provided PE file."""
    with open(file_path, "rb") as fobj:
        file_data = fobj.read()
        pe = pefile.PE(data=file_data)
        exec_sections, raw_bytes = [], []
        for section in pe.sections:
            if (
                pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
                & section.Characteristics
                == pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
            ):
                try:
                    name = section.Name.decode().rstrip("\x00")
                    name = name[:10]
                except Exception as _err:
                    name = "ERROR"
                exec_sections.append(
                    (
                        name,
                        section.PointerToRawData,
                        section.SizeOfRawData,
                        section.VirtualAddress,
                        section.Misc_VirtualSize,
                    )
                )
                fobj.seek(section.PointerToRawData)
                raw_bytes += fobj.read(section.SizeOfRawData)
        return raw_bytes, exec_sections


class MalConv2Model:
    def __init__(self, model_name: str = "malconv2_sstic_model.checkpoint") -> None:
        """Instanciate the MalConvModelHandler with provided `model_name` model.

        Note: The model must be in `models/` directory.
        """
        self.model = MalConvGCT(
            channels=256,
            window_size=256,
            stride=64,
        )
        try:
            model_file = Path(__file__).parent.resolve() / "models" / model_name
            x = torch.load(model_file, map_location=torch.device("cpu"))
        except FileNotFoundError:
            raise MalConv2ModelError(f"Cannot found the model file {model_file}")
        self.model.load_state_dict(x["model_state_dict"], strict=False)
        self.model.eval()

        # Getting out just the MLP
        self.mlp_model = Extracted_MLP()
        processed_dict = {}
        for k in ["fc_1.weight", "fc_1.bias", "fc_2.weight", "fc_2.bias"]:
            processed_dict[k] = self.model.state_dict()[k]
        self.mlp_model.load_state_dict(processed_dict)
        self.mlp_model.eval()

        # Instanciate the Explicability method
        self.dl = DeepLift(self.mlp_model)

    def __call__(self, filepath: str) -> tuple[np.ndarray, dict[str, float]]:
        raw_bytes = []
        if lief.is_pe(filepath):
            raw_bytes, exec_sections = get_exec_sections_pe(filepath)
        elif lief.is_elf(filepath):
            raw_bytes, exec_sections = get_exec_sections_elf(filepath)
        else:
            raise MalConv2ModelError("Neither a PE or an ELF executable file")

        try:
            x_np = (
                np.frombuffer(bytearray(raw_bytes), dtype=np.uint8).astype(np.int16) + 1
            )
            x_np = x_np.reshape((1, -1))
            if x_np.shape[1] < 2000:
                x_np = np.pad(x_np, ((0, 0), (0, 2000 - x_np.shape[1])), "constant")

            x = torch.Tensor(x_np).type(torch.int16)

            with torch.no_grad():
                post_conv, indices = self.model(x)
                output = self.mlp_model(post_conv)

            attr, _ = self.dl.attribute(post_conv, return_convergence_delta=True)
            attr = attr.detach().numpy()[0]

            _dict = {}

            heatmap = np.zeros((max(x_np.shape[1], 2000),), dtype=np.float32)
            for i in range(256):
                heatmap[indices[0][i]] += attr[i]
                if indices[0][i] in _dict:
                    _dict[indices[0][i]] += attr[i]
                else:
                    _dict[indices[0][i]] = attr[i]

            # Change the scale of the heatmap to fit the prediction of the model
            max_ = heatmap.max()
            min_ = heatmap.min() + 1e-12
            sum_p = heatmap[heatmap > 0].sum()
            sum_n = heatmap[heatmap < 0].sum()
            prediction = output.detach().numpy()[0]

        except Exception:
            raise MalConv2ModelError("Error while computing file prediction")

        try:
            heatmap[heatmap > 0] *= abs(prediction) / max_
            heatmap[heatmap < 0] *= abs(1.0 - prediction) / abs(min_)

            # Change also the functions scores to fit the prediction of the model
            _dict = {
                k: (v / sum_p) if v >= 0.0 else (v / abs(sum_n))
                for k, v in _dict.items()
            }

            filtered_dict = {k: v for k, v in _dict.items() if v > 0.0}
            sorted_dict = dict(
                sorted(filtered_dict.items(), key=lambda x: x[1], reverse=True)
            )

            # Change the dict key to be file's offsets
            functions_scores_by_offset = {}
            for key, value in sorted_dict.items():
                # Compute the offset in the section
                prev_size = 0
                for sec_name, sec_offset, sec_size, _, _ in exec_sections:
                    if key < prev_size + sec_size:
                        # The section is the one were the function is found
                        break
                    prev_size += sec_size
                functions_scores_by_offset[hex(key - prev_size + sec_offset)] = value

        except Exception:
            raise MalConv2ModelError("Error during function offset recuperation")

        return prediction, functions_scores_by_offset
