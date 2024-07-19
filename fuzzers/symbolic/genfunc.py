import numpy as np
import re
import os
import glob
import ilf.fuzzers.symbolic.ilfcfg as ilfcfg
import random
import numpy
import torch
import logging

from manticore.core.plugin import Plugin
from manticore.ethereum import ManticoreEVM, ABI


os.getcwd()

################ Variate #######################
node = ilfcfg.getnode('/home/fpx/go/src/ilf/example/toy.sol')
info = ilfcfg.cfginfo('/home/fpx/go/src/ilf/example/toy.sol','/home/fpx/go/src/ilf/example/Test.dot')
city = ilfcfg.cfginfo('/home/fpx/go/src/ilf/example/toy.sol','/home/fpx/go/src/ilf/example/Test.dot')[2]
matrix = ilfcfg.cfgmatrix(info[1],info[2])
distmat = dist_matrix = np.array(matrix)
distmatT = distmat.T
end_block = ilfcfg.findend(matrix,city)[0]
done = ilfcfg.findend(matrix,city)[1]
func_list = ilfcfg.astinfo(node)[0]
func_dict = ilfcfg.match_func_col('/home/fpx/go/src/ilf/example/Test.dot', func_list)

numant = 1  # 蚂蚁个数
# numcity = coordinates.shape[0]
# shape[0]=52 城市个数,也就是任务个数
numcity = len(city)
alpha = 1  # 信息素重要程度因子
beta = 5  # 启发函数重要程度因子
Q = 1  # 完成率
path = []
path3 = []
citypath = []
seed = []
seed2 = []

func_list = {}
result_dict = {}
new_dict = {}
output = ''

with open('/home/fpx/go/src/ilf/example/toy.sol', 'r') as file:
    source_code = file.read()

with open('/home/fpx/go/src/ilf/example/Test.dot', 'r') as file:
    blocks = file.read()  # 读取整个文件内容为一个字符串


################ Function #######################


def extract_block_content(blocks, end_block):
    pattern = re.compile(r'label="(\d+):.*?(STOP|REVERT)')
    matches = pattern.findall(blocks)
    if matches:
        return matches[1]
    else:
        return None


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

#检查文件中是否有---
def check_file_for_dashes(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            if '---' in line:
                return True
    return False

#提取文件中第二个---后的内容
def extract_content_after_second_dash(file_path):
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
def is_array_subset(arr1, arr2):
    set1 = set(arr1)
    set2 = set(arr2)
    
    return set1.issubset(set2)


def manticore_testcase(path2):
    tx = []

    for subseed in path2:

        if subseed in func_dict:
            call = func_dict[subseed]
            call_fun = call

            m = ManticoreEVM()
            p = EVMUseDef()
            m.register_plugin(p)

            # Initialize accounts
            user_account = m.create_account(balance=10000000)
            contract_account = m.solidity_create_contract(source_code, owner=user_account)
            md = m.get_metadata(contract_account)
            arg_type_by_name = {}
            sig_by_name = {}
            # sig = md.function_signatures
            # print("sig",sig,type(sig))
            # for s in sig:
            #    print(s)
            selector = md.function_selectors
            # print("selector",selector)
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

            
            for sub_end_block in end_block:
                content = extract_block_content(blocks, str(sub_end_block))

                if content:
                    result_dict[str(sub_end_block)] = content
                else:
                    print(f"Content not found for block {sub_end_block}.")

            for key, value in result_dict.items():
                if "REVERT" in value:
                    new_dict[key] = "REVERT"
                elif "STOP" in value:
                    new_dict[key] = "STOP"

            
            # 指定文件夹路径
            folder_path = m.workspace

            # # 获取所有.tx文件
            # file_pattern = os.path.join(folder_path, '*.tx')
            # tx_files = glob.glob(file_pattern)

            # # 遍历所有.tx文件并打开它们
            # for tx_file in tx_files:
            #     with open(tx_file, 'r') as f:
            #         content = f.read()
            #         function_calls = re.findall(r'.*->.*', content)
                
            #     print(function_calls)


            # 获取所有.trace文件
            file_pattern = os.path.join(folder_path, '*.trace')
            tr_files = glob.glob(file_pattern)
            #提取manticore生成的测试用例的执行路径
            for trfile in tr_files:
                traceblock = []
                has_dashes = check_file_for_dashes(trfile)
                if has_dashes:
                    extracted_content = extract_content_after_second_dash(trfile)
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
                traceblock = [x for x in traceblock if x in city]
                result = is_array_subset(path2, traceblock)

                if result:
                    txfile = trfile.replace('.trace', '.tx')
                    with open(txfile, 'r') as f:
                        content = f.read()
                        function_calls = re.findall(r'.*->.*', content)
                        functionname = function_calls[1].split(' ->')[0].split('(')[0]
                        argument = function_calls[1].split(' ->')[0].split('(')[1].split(')')[0]
                        tx.append(functionname)
                        tx.append(argument)
                
                # #根据stop和revert筛选测试用例
                # funccall = function_calls[0]
                # for i in range(1,len(function_calls)):
                #     funccall += ' -> ' + function_calls[i]
                

                # if new_dict[str(path2[-1])] in funccall:
                #     print(funccall) 
                # print('------------------------------------')
                
                

                    # 覆盖率
                    # for sub_call in function_calls:
                    #     if new_dict[str(path2[-1])] in sub_call:
                    #         new_list = []
                    #         for item in function_calls:
                    #             item = item.split(" -> ")[0]
                    #             new_list.append(item)
                    #         file_path = tx_file.replace(".tx", ".summary")
                    #         with open(file_path, 'r') as f:
                    #             txt = f.read()
                    #             pattern = r"(\d+)%.*"
                    #             match = re.search(pattern, txt)
                    #             code_coverage = float(match.group(1)) / 100
                    #             ins_coverage = len(path2) / len(city)
                    #             cov = ins_coverage * 0.5 + code_coverage * 0.5
                    #             coverage = [cov]
                    #             func_list[tuple(new_list)] = coverage
            # print(new_list)
    return tx


def aco(itermax):
    ################ Variate #######################
    global city
    global distmat
    iter = 0  # 迭代初始
    lengthaver = np.zeros(itermax)  # 迭代50次，存放每次迭代后，路径的平均长度  50*1
    lengthbest = np.zeros(itermax)  # 迭代50次，存放每次迭代后，最佳路径长度  50*1
    pathbest = np.zeros((itermax, numcity))  # 迭代50次，存放每次迭代后，最佳路径城市的坐标 50*52
    etatable = 1.0 / (distmat + np.diag([1e10] * numcity))
    # diag(),将一维数组转化为方阵 启发函数矩阵，表示蚂蚁从城市i转移到城市j的期望程度
    pheromonetable = np.ones((numcity, numcity))
    # 信息素矩阵 52*52
    pathtable = np.zeros((numant, numcity)).astype(int)

    while iter < itermax:
            # 迭代总数
        pathtable[:, 0] = city[0]
            # 40个蚂蚁随机放置于52个城市中

                # 先放52个
                # pathtable[numcity:, 0] = np.random.permutation(range(numcity))[:numant - numcity]
                # 再把剩下的放完
                # print(pathtable[:,0])
        length = np.zeros(numant)  # 1*40的数组

            # 本段程序算出每只/第i只蚂蚁转移到下一个城市的概率
        for i in range(numant):

                # i=0
            path1 = []
            visiting = pathtable[i, 0]  # 当前所在的城市
            path1.append(visiting)
            unvisited = set(range(numcity))
                # 剔除重复的元素
            unvisited.remove(visiting)  # 删除已经访问过的城市元素

            coverage = [0.01]
            for j in range(1, numcity):  # 循环numcity-1次，访问剩余的所有numcity-1个城市
                    # j=1
                    # 每次用轮盘法选择下一个要访问的城市
                listunvisited = list(unvisited)
                    # 未访问城市数,list
                probtrans = np.zeros(len(listunvisited))
                    # 每次循环都初始化转移概率矩阵1*52,1*51,1*50,1*49....

                    # 以下是计算转移概率
                for k in range(len(listunvisited)):
                    probtrans[k] = np.power(pheromonetable[visiting][listunvisited[k]], alpha) \
                                       * np.power(etatable[visiting][listunvisited[k]], alpha)
                    # eta-从城市i到城市j的启发因子 这是概率公式的分母   其中[visiting][listunvis[k]]是从本城市到k城市的信息素
                cumsumprobtrans = np.where(sum(probtrans) == 0, 0, (probtrans / sum(probtrans))).cumsum()
                    # 求出本只蚂蚁的转移到各个城市的概率斐波衲挈数列

                cumsumprobtrans -= np.random.rand()
                    # 随机生成下个城市的转移概率，再用区间比较
                    # k = listunvisited[find(cumsumprobtrans > 0)[0]]
                k = listunvisited[list(cumsumprobtrans > 0).index(True)]
                    # k = listunvisited[np.where(cumsumprobtrans > 0)[0]]
                    # where 函数选出符合cumsumprobtans>0的数
                    # 下一个要访问的城市

                pathtable[i, j] = k
                    # 采用禁忌表来记录蚂蚁i当前走过的第j城市的坐标，这里走了第j个城市.k是中间值
                unvisited.remove(k)
                    # visited.add(k)
                    # 将未访问城市列表中的K城市删去，增加到已访问城市列表中

                length[i] += distmat[visiting][k]
                    # 计算本城市到K城市的距离
                visiting = k
                path1.append(visiting)
                if visiting in done:
                    break
            path.append(path1)
            path2 = []
            for subpath in range(len(path1)):
                path2.append(city[path1[subpath]])

                # 根据生成的cfg路径生成测试用例
            print(path2)
            tx = manticore_testcase(path2)

            pairs = []

            for node in range(len(path1) - 1):
                pair = (path1[node], path1[node + 1])
                pairs.append(pair)
                # print(pairs)
                # 设置特定位置的元素为 0.14
            for pos in pairs:
                row, col = pos
                    # etatable[row, col] = coverage[0]

                etatable[row, col] = 1.0 / (distmat[row, col] + [1e10] + coverage[0])

                    # etatable = 1.0 / (distmat + np.diag([1e10] * numcity))

                # # 将其余元素设置为 0.001
                # etatable[etatable != coverage[0]] = 0.001

            # print(coverage)

        length[i] += distmat[visiting][pathtable[i, 0]]
            # 计算本只蚂蚁的总的路径距离，包括最后一个城市和第一个城市的距离

            # print("ants all length:",length)
            # 包含所有蚂蚁的一个迭代结束后，统计本次迭代的若干统计参数

        lengthaver[iter] = length.mean()
            # 本轮的平均路径

            # 本部分是为了求出最佳路径

        if iter == 0:
                lengthbest[iter] = length.min()
                pathbest[iter] = pathtable[length.argmin()].copy()
            # 如果是第一轮路径，则选择本轮最短的路径,并返回索引值下标，并将其记录
        else:
                # 后面几轮的情况，更新最佳路径
            if length.min() > lengthbest[iter - 1]:
                    lengthbest[iter] = lengthbest[iter - 1]
                    pathbest[iter] = pathbest[iter - 1].copy()
                # 如果是第一轮路径，则选择本轮最短的路径,并返回索引值下标，并将其记录
            else:
                    lengthbest[iter] = length.min()
                    pathbest[iter] = pathtable[length.argmin()].copy()

            # 此部分是为了更新信息素
        changepheromonetable = np.zeros((numcity, numcity))
        for i in range(numant):  # 更新所有的蚂蚁
            for j in range(numcity - 1):
                    changepheromonetable[pathtable[i, j]][pathtable[i, j + 1]] += Q / distmat[pathtable[i, j]][
                        pathtable[i, j + 1]]
                    # 根据公式更新本只蚂蚁改变的城市间的信息素      Q/d   其中d是从第j个城市到第j+1个城市的距离
            changepheromonetable[pathtable[i, j + 1]][pathtable[i, 0]] += Q / distmat[pathtable[i, j + 1]][
                    pathtable[i, 0]]
                # 首城市到最后一个城市 所有蚂蚁改变的信息素总和
        rho = 0.5
            # 信息素更新公式p=(1-挥发速率)*现有信息素+改变的信息素
        pheromonetable = (1 - rho) * pheromonetable + changepheromonetable

        iter += 1  # 迭代次数指示器+1
        print("this iteration end：", iter)
            # 观察程序执行进度，该功能是非必须的
        if (iter - 1) % 20 == 0:
            print("schedule:", iter - 1)
        # for sublist in path:
        #     print(sublist)
        #     new_sublist = [city[index] for index in sublist]
        #     seed.append(new_sublist)
        # city ,distmat= cut(city,path,distmat)
        # seed2.append(path[-1])
        # print(seed2)
    return seed,tx

# ################ Main #######################
seed = aco(1)
print(seed[1][0])
print(seed[1][1])


