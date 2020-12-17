import os

files = os.popen("ls | grep pcap")

flag = True
for name in files:
    if len(name) <= 0:
        continue
    if flag: # payload -  -e _ws.col.Info
        p = "tshark -r ./" + name[:-1] + " -T fields -E separator=, -E header=y -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto -e frame.len -e _ws.col.Info > " + name.split('.')[0] + ".csv"
    else:
        p = "tshark -r ./" + name[:-1] + " -T fields -E separator=, -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto -e frame.len -e _ws.col.Info > " + name.split('.')[0] + ".csv"
    flag = False
    print(p)
    os.system(p)


os.system("ls | grep csv")

import csv
import glob

files = os.popen("ls | grep csv")

merge_path = "./raw_merge.csv"

total = 0
with open(merge_path, 'w') as f: #2-1.merge할 파일을 열고
    for name in files: 
        print("./" + name[:-1])
        if name[:-1] == "raw_merge.csv":
            continue
        with open("./" + name[:-1] ,'r') as f2:
            cnt = 0 
            while True:
                line = f2.readline() #2.merge 대상 파일의 row 1줄을 읽어서 
                cnt += 1
                if not line: #row가 없으면 해당 csv 파일 읽기 끝 
                    break
                f.write(line) #3.읽은 row 1줄을 merge할 파일에 쓴다.
        total += cnt
        print(cnt)
        os.system("rm " + name[:-1])
print("Total - ", total)

