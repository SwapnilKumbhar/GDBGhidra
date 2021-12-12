"""
Entrypoint for the GDB plugin
"""
import subprocess
import platform
import os
import logging
import glob
import json
from elftools.elf.elffile import ELFFile

logging.basicConfig(
    format="%(levelname)s [%(funcName)s:%(lineno)d] - %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.WARNING,
)

logger = logging.getLogger(__name__)

try:
    import r2pipe
except ImportError as e:
    logger.error("This project needs `r2pipe` as a dependency")
    exit(-1)

################################################################################
# Initial Checks
################################################################################


def _checkR2Executable() -> bool:
    """
    Checks if r2 exists in the path
    :return: Bool
    """
    paths = os.environ.get("PATH").split(":")
    for path in paths:
        logger.info(f"Checking {path} for r2...")
        if len(glob.glob(os.path.join(path, "r2"))) != 0:
            logger.info(f"Found r2 in {path}")
            return True
    return False


def _checkR2Ghidra() -> bool:
    """
    Check if r2ghidra exists. We do this by checking in the R2_LIBR_PLUGINS directory for specific libraries.
    :return:
    """
    p = subprocess.Popen(["r2", "-H"], stdout=subprocess.PIPE)
    ghidraObjects = ["anal_ghidra", "asm_ghidra", "core_ghidra"]
    ext = ""
    if platform.system() == "Linux":
        ext = ".so"
    elif platform.system() == "Darwin":
        ext = ".dylib"
    elif platform.system() == "Windows":
        ext = ".dll"
    ghidraObjects = list(map(lambda x: x + ext, ghidraObjects))
    for line in p.stdout.readlines():
        line = line.decode().rstrip()
        if line.startswith("R2_LIBR_PLUGINS"):
            # Check if Ghidra files exist
            path = line.split("=")[1]
            logger.info(f"Found R2_LIBR_PLUGINS at: {path}")
            objs = glob.glob(os.path.join(path + f"/*{ext}"))
            objs.sort()
            objs = list(map(os.path.basename, objs))
            logger.info(f"Found these objects: {objs}")
            if ghidraObjects == objs:
                return True
    return False


def check() -> bool:
    """
    Checks the following
    1. Check if r2 is installed
    2. Check if r2 has r2ghidra installed as a plugin.
    :return: None
    """
    if not _checkR2Executable():
        logger.error("You need r2 to run this plugin. Is it installed? Is it in $PATH?")
        return False
    if not _checkR2Ghidra():
        logger.error(
            "This plugin uses r2ghidra in the backend. Could not find r2ghidra files, please install it"
        )
        return False
    # All good.
    return True


################################################################################
# GDB Command
################################################################################


class DecompileGhidra(gdb.Command):
    r2 = None
    logger: logging.Logger = None
    _fnCache: dict = {}

    def __init__(self):
        super(DecompileGhidra, self).__init__("decompileGhidra", gdb.COMMAND_USER)
        self.logger = logging.getLogger()

    def _isRunning(self):
        # Return true if there is at least one running thread
        return True if len(gdb.selected_inferior().threads()) > 0 else False

    def _initPipe(self):
        targetFile = gdb.selected_inferior().progspace.filename
        flags = []
        # Check if PIE and change base address
        with open(targetFile, "rb") as targetFd:
            targetElf = ELFFile(targetFd)
            if targetElf.header.e_type == "ET_DYN":
                # We are relative
                # I'll find a better way to do this in the future
                logger.info("Binary is PIE")
                lines: list[str] = gdb.execute("info files", False, True).split("\n")
                for line in lines:
                    if "Entry point" in line:
                        baseAddr = line.lstrip().replace("Entry point: ", "")
                        logger.info(f"Base address is: {baseAddr}")
                        flags = ["-B", baseAddr]
                        break
        if targetFile is not None:
            # Initialize the pipe
            logger.info(f"Initializing r2 with flags: {flags}")
            self.r2 = r2pipe.open(targetFile, flags=flags)
            self.r2.cmd("aaaa")

        logger.info("Constructing Function Cache")
        # Build function cache
        fns = json.loads(self.r2.cmd("aflj"))
        for fn in fns:
            if fn["name"] == "entry0":
                self._fnCache["_start"] = fn["offset"]
            else:
                self._fnCache[fn["name"]] = fn["offset"]

    def _fnLookupSymbol(self, symbol: str) -> str:
        logger.info(f"Looking up symbol: {symbol}")
        for k, v in enumerate(self._fnCache):
            logger.info(f"{k} - {v}")
            if symbol in v:
                return str(v)
        return None

    def _r2Decompile(self, address: str) -> str:
        self.r2.cmd(f"s {address}")
        return self.r2.cmd("pdg")

    def _decompileCurrent(self):
        if not self.r2:
            self._initPipe()

        if not self._isRunning():
            self.logger.error(
                "No inferiors active, please specify address for decompilation."
            )
            return

        currentAddr = hex(gdb.selected_frame().pc())
        print(self._r2Decompile(currentAddr))

    def invoke(self, addr: str, from_tty: bool):
        if not self.r2:
            self._initPipe()
        if addr == "":
            # If no address is given, decompile the current address
            self._decompileCurrent()
            return
        # Check if address is a symbol or a hex address
        logger.info(f"Attempting to decompile: {addr}")
        try:
            addr = int(addr, 16)
            print(self._r2Decompile(addr))
            return
        except ValueError:
            pass
        # If not a number, lets try to look it up
        fnAddr = self._fnLookupSymbol(addr)
        if fnAddr is not None:
            print(self._r2Decompile(fnAddr))
            return
        print(self._r2Decompile(addr))


DecompileGhidra()
################################################################################
# Main
################################################################################

if __name__ == "__main__":
    # Check if we have r2ghidra files on the disk
    if not check():
        exit(-1)
    logger.info("We good to go!")
