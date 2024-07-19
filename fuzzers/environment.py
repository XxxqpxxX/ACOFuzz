import random
import numpy
import torch
import logging
import numpy as np
import re
import os
import glob
import ilf.fuzzers.symbolic.ilfcfg as ilfcfg

from ..execution import Execution, Tx
from ..ethereum import Method
from .random import PolicyRandom
from .symbolic import PolicySymbolic
from .sym_plus import PolicySymPlus
from .mix import PolicyMix, ObsMix
from .imitation import PolicyImitation

from manticore.core.plugin import Plugin
from manticore.ethereum import ManticoreEVM, ABI

LOG = logging.getLogger(__name__)

class EVMUseDef(Plugin):
    def did_evm_write_storage_callback(self, state, address, offset, value):
        m = self.manticore
        world = state.platform
        tx = world.all_transactions[-1]
        md = m.get_metadata(tx.address)
        current_loc = m.current_location(state)
        sv = world.get_storage(tx.address)
        if md:
            offsets = state.solve_n(offset, 3000)
            with self.locked_context("storage_writes", dict) as storage_writes:
                contract_function = (md.name, md.get_func_name(state.solve_one(tx.data[0:4])))
                if contract_function not in storage_writes:
                    storage_writes[contract_function] = set()
                # for off in offsets:
                #    storage_writes[contract_function].add(off)

    def did_evm_read_storage_callback(self, state, address, offset, value):
        m = self.manticore
        world = state.platform
        tx = world.all_transactions[-1]
        md = m.get_metadata(tx.address)
        if md:
            offsets = state.solve_n(offset, 3000)
            with self.locked_context("storage_reads", dict) as storage_reads:
                contract_function = (md.name, md.get_func_name(state.solve_one(tx.data[0:4])))
                if contract_function not in storage_reads:
                    storage_reads[contract_function] = set()
                # for off in offsets:
                #    storage_reads[contract_function].add(off)

class Environment:

    def getfunc(self, filedir):
            funclist = {}
            pattern = r'(\d+)\[label="Function name: (.+?)\('
            with open(filedir, 'r') as f:
                    content = f.read()
                    matches = re.findall(pattern, content)
            # 打印匹配结果
            for match in matches:
                funclist[match[0]] = match[1]
            return funclist

    def __init__(self, limit, seed, contract):
        self.limit = limit
        self.seed = seed
        self.contract = contract
    
        self.node = ilfcfg.getnode('/home/fpx/go/src/ilf/example/' + self.contract + '.sol')
        self.info = ilfcfg.cfginfo('/home/fpx/go/src/ilf/example/' + self.contract + '.sol','/home/fpx/go/src/ilf/example/' + self.contract + '.dot')
        self.city = ilfcfg.cfginfo('/home/fpx/go/src/ilf/example/' + self.contract + '.sol','/home/fpx/go/src/ilf/example/' + self.contract + '.dot')[2]
        self.matrix = ilfcfg.cfgmatrix(self.info[1],self.info[2])
        self.distmat = dist_matrix = np.array(self.matrix)
        self.distmatT = self.distmat.T
        self.end_block = ilfcfg.findend(self.matrix,self.city)[0]
        self.done = ilfcfg.findend(self.matrix,self.city)[1]
        self.func_list = ilfcfg.astinfo(self.node)[0]
        self.func_dict = ilfcfg.match_func_col('/home/fpx/go/src/ilf/example/' + self.contract + '.dot', self.func_list)

        self.donelist = []
        #Distance距离矩阵
        self.Distance = self.distmat

        # 蚂蚁数量
        self.AntCount = 10
        # 城市数量
        self.city_count = len(self.city)
        # 信息素
        self.alpha = 1  # 信息素重要程度因子
        self.beta = 2  # 启发函数重要程度因子
        self.rho = 0.1 #挥发速度
        self.iter = 0  # 迭代初始值
        self.Q = 1
        self.citypath = []
        self.seed2 = []
        self.func_list = {}
        self.result_dict = {}
        self.new_dict = {}
        self.output = ''
        self.func_dict = self.getfunc('/home/fpx/go/src/ilf/example/' + self.contract + '.dot')


    def extract_block_content(self, blocks, end_block):
        pattern = re.compile(r'label="(\d+):.*?(STOP|REVERT)')
        matches = pattern.findall(blocks)
        if matches:
            return matches[1]
        else:
            return None

    #检查文件中是否有---
    def check_file_for_dashes(self, file_path):
        with open(file_path, 'r') as file:
            for line in file:
                if '---' in line:
                    return True
        return False

    #提取文件中第二个---后的内容
    def extract_content_after_second_dash(self, file_path):
        with open(file_path, 'r') as file:
            lines = file.readlines()

        dash_count = 0
        content = []
        for line in lines:
            if line.strip() == '---':
                dash_count += 1
                if dash_count == 2:
                    content = []
            elif dash_count == 2:
                content.append(line)

        return ''.join(content).strip()

    #判断节点是否都在trace文件中
    def is_array_subset(self, arr1, arr2):
        set1 = set(arr1)
        set2 = set(arr2)
        
        return set1.issubset(set2)
    
    def manticore_testcase(self, path2, source_code, blocks):
        tx = []

        for subseed in path2:

            if str(subseed) in self.func_dict:
                call = self.func_dict[str(subseed)]
                call_fun = call

                m = ManticoreEVM()
                p = EVMUseDef()
                m.register_plugin(p)

                # Initialize accounts
                user_account = m.create_account(balance=10000000)
                contract_account = m.solidity_create_contract(source_code, owner=user_account, contract_name= self.contract)
                md = m.get_metadata(contract_account)
                arg_type_by_name = {}
                sig_by_name = {}
                selector = md.function_selectors
                for se in selector:
                    func_name = md.get_func_name(se)
                    arg_type_by_name[func_name] = md.get_func_argument_types(se)
                    sig_by_name[func_name] = md.get_func_signature(se)
                arg_type = arg_type_by_name[call_fun]
                args = m.make_symbolic_arguments(arg_type)
                tx_data = ABI.function_call(str(sig_by_name[call_fun]), *args)
                symbolic_data = m.make_symbolic_buffer(320)
                symbolic_value = m.make_symbolic_value()
                
                m.transaction(caller=user_account, address=contract_account, value=symbolic_value, data=tx_data)

                m.finalize()
                print(f"[+] Look for results in {m.workspace}")

                
                for sub_end_block in self.end_block:
                    content = self.extract_block_content(blocks, str(sub_end_block))

                    if content:
                        self.result_dict[str(sub_end_block)] = content
                    else:
                        print(f"Content not found for block {sub_end_block}.")

                for key, value in self.result_dict.items():
                    if "REVERT" in value:
                        self.new_dict[key] = "REVERT"
                    elif "STOP" in value:
                        self.new_dict[key] = "STOP"

                
                # 指定文件夹路径
                folder_path = m.workspace

                # 获取所有.trace文件
                file_pattern = os.path.join(folder_path, '*.trace')
                tr_files = glob.glob(file_pattern)
                #提取manticore生成的测试用例的执行路径
                for trfile in tr_files:
                    traceblock = []
                    has_dashes = self.check_file_for_dashes(trfile)
                    if has_dashes:
                        extracted_content = self.extract_content_after_second_dash(trfile)
                        pattern = r":([a-zA-Z0-9]+)"
                        matches = re.findall(pattern, extracted_content)
    
                        for match in matches:
                            traceblock.append(int(match,16))
                    else:
                        with open(trfile, 'r') as file:
                            pattern = r":([a-zA-Z0-9]+)"
                            matches = re.findall(pattern, extracted_content)

                            for match in matches:
                                traceblock.append(int(match,16))
                    
                    traceblock = [x for x in traceblock if x in self.city]
                    result = self.is_array_subset(path2, traceblock)

                    if result:
                        txfile = trfile.replace('.trace', '.tx')
                        with open(txfile, 'r') as f:
                            content = f.read()
                            function_calls = re.findall(r'.*->.*', content)
                            functionname = function_calls[1].split(' ->')[0].split('(')[0]
                            argument = function_calls[1].split(' ->')[0].split('(')[1].split(')')[0]
                            tx.append(functionname)
                            tx.append(argument)
        return tx
    
    def fuzz_loop(self, policy, obs):

        with open('/home/fpx/go/src/ilf/example/' + self.contract + '.sol', 'r') as file:
            source_code = file.read()

        with open('/home/fpx/go/src/ilf/example/' + self.contract + '.dot', 'r') as file:
            blocks = file.read()  # 读取整个文件内容为一个字符串

        obs.init()

        LOG.info(obs.stat)
        LOG.info('initial calls start')
        self.init_txs(policy, obs)
        LOG.info('initial calls end')

        random.seed(self.seed)
        torch.manual_seed(self.seed)
        numpy.random.seed(self.seed)

        ################ Variate #######################
        global city
        global distmat
        iter = 0  # 迭代初始
        done_node = []
        global coverage
        coverage_all = []
        global coverage_up
        coverage_up = []
        
        pheromonetable = np.ones((self.city_count, self.city_count))

        # 倒数矩阵
        etable = 1.0 / self.Distance 
        

        while iter < self.limit:
            # first：蚂蚁初始点选择
            length = np.zeros(self.AntCount)#每次迭代的N个蚂蚁的距离值
            path = []
            # second：选择下一个城市选择
            antpath = []
            for i in range(self.AntCount):
                # 移除已经访问的第一个元素

                seedpath = [0]
                unvisit = list(range(self.city_count))  # 列表形式存储没有访问的城市编号
                visit = 0  # 当前所在点,第i个蚂蚁在第一个城市
                unvisit.remove(visit)  # 在未访问的城市中移除当前开始的点
                for j in range(1, self.city_count):#访问剩下的city_count个城市，city_count次访问
                    if visit in self.done:
                        break
                    else:
                        protrans = np.zeros(len(unvisit))#每次循环都更改当前没有访问的城市的转移概率矩阵1*30,1*29,1*28...
                        # 下一城市的概率函数
                        for k in range(len(unvisit)):
                            # 计算当前城市到剩余城市的（信息素浓度^alpha）*（城市适应度的倒数）^beta
                            # etable[visit][unvisit[k]],(alpha+1)是倒数分之一，pheromonetable[visit][unvisit[k]]是从本城市到k城市的信息素
                            protrans[k] = np.power(pheromonetable[visit][unvisit[k]], self.alpha) * np.power(
                                etable[visit][unvisit[k]], (self.alpha + 1))

                        # 累计概率，轮盘赌选择
                        cumsumprobtrans = (protrans / sum(protrans)).cumsum()
                        cumsumprobtrans -= np.random.rand()
                        # 求出离随机数产生最近的索引值sssssss
                        k = unvisit[list(cumsumprobtrans > 0).index(True)]
                        unvisit.remove(k)
                        length[i] += self.Distance[visit][k]
                        visit = k  # 更改出发点，继续选择下一个到达点
                        seedpath.append(k)
                antpath.append(seedpath)
                
            path.append(antpath)
        
            
        


            # 信息素的更新
            # 信息素的增加量矩阵
            changepheromonetable = np.zeros((self.city_count, self.city_count))
            for antindex in range(self.AntCount):
                for nodeindex in range(len(path[0][antindex])-1):
                    changepheromonetable[path[0][antindex][nodeindex]][path[0][antindex][nodeindex + 1]] += self.Q * length[antindex]
            pheromonetable = (1 - self.rho) * pheromonetable + changepheromonetable
            print('----------' + str(iter) + '---------')   
            for antindex in range(self.AntCount):
                for nodeindex in range(len(path[0][antindex])):
                    path[0][antindex][nodeindex] = self.city[path[0][antindex][nodeindex]]
            print(path)

        
            for antindex in range(self.AntCount):
                if path[0][antindex] not in self.donelist:
                    funccall = self.manticore_testcase(path[0][antindex], source_code, blocks)
                    if funccall:
                        methodname = funccall[0]
                        argument = funccall[1]
                        arguments = [argument]
                    
                        tx = policy.acoselect_tx(obs, methodname, arguments)
                        for i in range(len(path[0][antindex])):
                            done_node.append(path[0][antindex][i])
                            coverage = len(set(done_node)) / len(self.city)
                            logger = policy.execution.commit_tx(tx)
                        coverage_up = obs.acoupdate(logger, False, coverage, coverage_up)
                    self.donelist.append(path[0][antindex])
                    print(obs.stat)
                else:
                    if policy.__class__ in (PolicyRandom, PolicyImitation) and iter > self.limit // 2:
                        for contract_name in policy.contract_manager.fuzz_contract_names:
                            contract = policy.contract_manager[contract_name]
                            policy.execution.set_balance(contract.addresses[0], 10 ** 29)

                    tx = policy.select_tx(obs)
                    for i in range(len(path[0][antindex])):
                            done_node.append(path[0][antindex][i])
                            coverage = len(set(done_node)) / len(self.city)
                            logger = policy.execution.commit_tx(tx)
                    
                    if tx is None:
                        break

                    logger = policy.execution.commit_tx(tx)
                    old_insn_coverage = obs.stat.get_insn_coverage(tx.contract)
                    coverage_up = obs.update(logger, False, coverage, coverage_up)
                    new_insn_coverage = obs.stat.get_insn_coverage(tx.contract)

                    if policy.__class__ in (PolicySymbolic, PolicySymPlus) and new_insn_coverage - old_insn_coverage < 1e-5:
                        break

                    # LOG.info(obs.stat)
                    print(obs.stat)

                    if policy.__class__ not in (PolicySymbolic, PolicySymPlus) and iter % 50 == 0:
                        policy.reset()
                        if policy.__class__ == PolicyImitation:
                            policy.clear_history()
                        if policy.__class__ == PolicyMix and policy.policy_fuzz.__class__ == PolicyImitation:
                            policy.policy_fuzz.clear_history()
                        if obs.__class__ == ObsMix:
                            obs.reset()
            iter += 1
        print(coverage_all)
        print(len(coverage_all))
        print(coverage_up)


    def init_txs(self, policy, obs):
        coverage_up = []
        coverage = 0
        policy_random = PolicyRandom(policy.execution, policy.contract_manager, policy.account_manager)
        for name in policy.contract_manager.fuzz_contract_names:
            contract = policy.contract_manager[name]
            if Method.FALLBACK not in contract.abi.methods_by_name:
                tx = Tx(policy_random, contract.name, contract.addresses[0], Method.FALLBACK, bytes(), [], 0, 0, 0, True)
                logger = policy_random.execution.commit_tx(tx)
                obs.update(logger, True,coverage,coverage_up)
                LOG.info(obs.stat)

            for method in contract.abi.methods:
                if not contract.is_payable(method.name):
                    tx = policy_random.select_tx_for_method(contract, method, obs)
                    tx.amount = 1
                    logger = policy_random.execution.commit_tx(tx)
                    obs.update(logger, True,coverage,coverage_up)
                    LOG.info(obs.stat)