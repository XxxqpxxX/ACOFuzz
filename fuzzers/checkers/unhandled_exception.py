from .checker import Checker
from ...ethereum import REVERT, INVALID
from ilf.ethereum.evm.contract import *

class UnhandledException(Checker):

    def __init__(self, contract_manager, account_manager):
        super().__init__()
        self.contract_manager = contract_manager
        self.account_manager = account_manager
        self.list=[]
        self.path=[]
    def check(self, logger):
        find =False
        has_exception = False

        for _, log in enumerate(logger.logs):
            if (log.op in (REVERT, INVALID) or log.error != '') and log.depth > 1:
                has_exception = True

        if has_exception and logger.logs[-1].op not in (REVERT, INVALID) and logger.logs[-1].error == '':
            find = True
            if find:
                return True
        else:
            return False
