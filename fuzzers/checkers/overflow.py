from .checker import Checker
from ...ethereum import *
from ilf.ethereum.evm.contract import *
from ilf.ethereum.analysis import CFG

class overflow(Checker):

    def __init__(self, contract_manager, account_manager):
        super().__init__()
        self.contract_manager = contract_manager
        self.account_manager = account_manager

    def check(self, logger):
        for log in logger.logs:
            if log.op == ADD:
                if ((int(log.stack[0], 16)+int(log.stack[1], 16)) > 0xffffffffffffffff):                 
                    return True    
            if log.op == SUB:
                if ((int(log.stack[0], 16) - int(log.stack[1], 16)) < 0) :   
                    return True                
            if log.op == MUL: 
                if ((int(log.stack[0], 16)*(int(log.stack[1], 16))) > 0xffffffffffffffff):              
                    return True
                
            if log.op == MOD :

                if int(log.stack[1], 16) == 0 or ((int(log.stack[0], 16) % int(log.stack[1], 16)) > 0xffffffffffffffff):           
                    return True  

            if log.op == DIV:
                if log.stack and len(log.stack) >= 3:
                    if int(log.stack[1], 16) == 0 or ((int(log.stack[0], 16))//(int(log.stack[1], 16))> 0xffffffffffffffff)or((int(log.stack[0], 16)) > 0xffffffffffffffff):
                        return True
        return False

