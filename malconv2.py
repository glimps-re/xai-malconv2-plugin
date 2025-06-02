# Standard
import warnings
import logging
import os
import json
import re
from pathlib import Path

# IDA-related
import ida_nalt
import idaapi
import idc
import ida_kernwin

# Custom
from malconv2.model import MalConv2Model

# Avoid python warnings in IDA output terminal
warnings.filterwarnings("ignore")


# Plugin Configuration file
if os.name == "nt":
    PLUGIN_CONFIG_FILE = Path(os.environ["APPDATA"]) / ".malconv2.conf"
else:
    PLUGIN_CONFIG_FILE = Path(__file__).parent.resolve() / ".malconv2.conf"

# Define default plugin values to use
DEFAULT_PLUGIN_CONFIG = {
    "IgnoreOffsets": False,
    "MaxMalFunc": "100",
    "MinFuncContrib": "0.02",
}

# Configuration form text content
SETTINGS_FORM_TEXT = r"""
Malconv2 explainability configuration
{FormChangeCall}

<Don't show function offsets: {offsets}>{IgnoreOffsets}>

< %40s {MaxMalFunc}>

< %40s {MinFuncContrib}>

""" % (
    "Maximal nb of functions to show (int):",
    "Min function contrib to show (float):",
)


class MalConv2Configuration(ida_kernwin.Form):
    """IDA configuration panel for MalConv2 explainability plugin."""

    def __init__(self):
        """Instanciate the configuration panel."""
        # Numerical values are treated as str for simplicity
        # the content is verified once the form is submitted.
        dd = {
            "FormChangeCall": ida_kernwin.Form.FormChangeCb(self.OnFormChange),
            "IgnoreOffsets": ida_kernwin.Form.ChkGroupControl(("all", "offsets")),
            "MaxMalFunc": ida_kernwin.Form.StringInput(width=5, swidth=5),
            "MinFuncContrib": ida_kernwin.Form.StringInput(width=5, swidth=5),
        }
        ida_kernwin.Form.__init__(self, SETTINGS_FORM_TEXT, dd)
        self.save_cache = True
        self.show_dialog = True

    def OnFormChange(self, fid):
        return 1


class MalConv2Plugin(idaapi.plugin_t):
    """Core of MalConv2 plugin."""

    flags = idaapi.PLUGIN_KEEP
    wanted_name = "MalConv2 settings"
    comment = "Provide Malware detection and explaination at function level"
    help = "Provide Malware detection and explaination at function level"

    def init(self):
        """Instantiate the configuration panel and action button."""
        # Instantiate a default configuration for the plugin
        self._defaut_config = DEFAULT_PLUGIN_CONFIG
        # Create initial config file if it doesn't exists
        if PLUGIN_CONFIG_FILE.exists():
            self._config = self._load_configuration()
        else:
            print(
                f"{self.wanted_name} plugin config file not found at {PLUGIN_CONFIG_FILE}, using defaults"
            )
            self._config = self._defaut_config.copy()
            self._save_configuration()

        # Create a new entry in IDA Edit to start the analysis
        self.malconv2_explain_act = MalConv2PluginMod(self)
        malconv2_explain = idaapi.action_desc_t(
            "my:explainability",
            "Start explainability process",
            self.malconv2_explain_act,
            None,
            "Start explainability process",
        )
        idaapi.register_action(malconv2_explain)

        idaapi.attach_action_to_menu(
            "Edit/MalConv2/Start Explainability",
            "my:explainability",
            idaapi.SETMENU_APP,
        )

        return idaapi.PLUGIN_KEEP

    @property
    def config(self):
        return self._load_configuration()

    @property
    def default_config(self):
        return self._default_config

    def term(self):
        return

    def run(self, arg):
        self._display_configuration()

    def _save_configuration(self):
        """Save the plugin configuration to a json file."""
        with open(PLUGIN_CONFIG_FILE, "w") as f_config_file:
            config_file_data = json.dumps(self._config)
            f_config_file.write(config_file_data)

    def _load_configuration(self):
        """Load the plugin configuration."""
        if PLUGIN_CONFIG_FILE.exists():
            with open(PLUGIN_CONFIG_FILE, "r") as f_config_file:
                config_file_data = f_config_file.read()
                _config = json.loads(config_file_data)
                return _config
        else:
            return None

    def _display_configuration(self):
        """Display configuration panel and post-process its content.

        - If Numerical fields are not correct, use default values for the analysis.
        - Update the configuration file to keep this configuration after restart.
        """
        confFrom = MalConv2Configuration()
        confFrom.Compile()
        confFrom.IgnoreOffsets.value = bool(self._config["IgnoreOffsets"])
        confFrom.MaxMalFunc.value = self._config["MaxMalFunc"]
        confFrom.MinFuncContrib.value = self._config["MinFuncContrib"]
        if confFrom.Execute() == 1:
            self._config["IgnoreOffsets"] = bool(confFrom.IgnoreOffsets.value)
            if confFrom.MaxMalFunc.value.isdigit():
                self._config["MaxMalFunc"] = confFrom.MaxMalFunc.value
            else:
                logging.warning("Nb Maximal functions is not an integer, default used.")
                self._config["MaxMalFunc"] = self._defaut_config["MaxMalFunc"]
            if re.match(r"^\d+.\d+$", confFrom.MinFuncContrib.value):
                self._config["MinFuncContrib"] = confFrom.MinFuncContrib.value
            else:
                logging.warning(
                    "Minimal function contribution is not a float, default used."
                )
                self._config["MinFuncContrib"] = self._defaut_config["MinFuncContrib"]
            self._save_configuration()
            self.malconv2_explain_act.run()


class MalConv2PluginMod(idaapi.action_handler_t):
    """Implement MalConv2 explainability process."""

    def __init__(self, plugin: MalConv2Plugin):
        """Instanciate the explainability process with parent plugin to keep track of the current configuration."""
        idaapi.action_handler_t.__init__(self)
        self.banner = "\n\n###### MalConv2 /w explainability by GLIMPS ######\n"
        self.separator = "-----------------------------------------------"
        self.plugin = plugin

    def activate(self, ctx):
        self.run()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def run(self):
        """Predict malware behavior and show important functions if detected as malicious."""
        print(self.banner)
        # Get the full path of the currently opened file
        file_path = ida_nalt.get_input_file_path()
        if file_path is None:
            logging.error("Please open a binary file before to analyse.")
            return False

        # Get actual configuration
        config = self.plugin.config
        if not config:
            logging.warning("MalConv2 plugin is not configured. Defaut settings used")
            config = DEFAULT_PLUGIN_CONFIG

        glimps_malconv2_model = MalConv2Model()
        prediction, functions_scores_by_offset = glimps_malconv2_model(file_path)

        if prediction < 0.5:
            print("Considered as legitimate by the model - no function ranking.")
            return True

        by_functions = {}

        for offset, score in functions_scores_by_offset.items():
            func_name, func_start_ea = self._get_function_name_at_offset(
                int(offset, 16), float(score), verbose=not config["IgnoreOffsets"]
            )
            if func_name is None:
                if "" in by_functions.keys():
                    by_functions[""]["score"] += float(score)
                else:
                    by_functions[""] = {
                        "name": "<offset_not_in_function>",
                        "score": float(score),
                    }
            elif func_start_ea in by_functions.keys():
                by_functions[func_start_ea]["score"] += float(score)
            else:
                by_functions[func_start_ea] = {"name": func_name, "score": float(score)}

        print(
            f"{self.separator}\nMalware prediction {prediction:.4f}\n{self.separator}"
        )

        func_by_score = sorted(
            by_functions.items(), key=lambda a: a[1]["score"], reverse=True
        )

        max_func = int(config["MaxMalFunc"])
        if max_func <= 0:
            max_func = len(func_by_score)

        for _, func in func_by_score[:max_func]:
            if func["score"] < float(config["MinFuncContrib"]):
                break
            print(func["name"], f"{func['score']:.3f}")

        return True

    def _get_function_name_at_offset(self, file_offset, score, verbose=True):
        """Associate offsets to functions."""
        # Convert file offset to virtual address
        ea = idaapi.get_fileregion_ea(file_offset)

        if ea == idc.BADADDR:
            logging.error("Invalid file offset.")
            return None, None

        # Check if the address belongs to a function
        func = idaapi.get_func(ea)

        comment = (
            f"The offset 0x{file_offset:X} with explainability score {score:4f} is "
        )

        if func is None:
            if verbose:
                print(comment + "not within any function.")
            return None, None

        # Get the function name
        func_name = idc.get_func_name(func.start_ea)

        if func_name:
            if verbose:
                print(comment + f"within the function: {func_name}")
            return func_name, func.start_ea

        if verbose:
            print(f"Function name not found for the offset 0x{file_offset:X}.")
        return None, None


def PLUGIN_ENTRY():
    return MalConv2Plugin()
