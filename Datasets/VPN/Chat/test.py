import csv
import glob


merge_path = "./raw_merge.csv"

with open(merge_path, 'r') as f: #2-1.merge할 파일을 열고
    with open("./merge.csv" ,'w') as f2:
        while True:
            line = f.readline() #2.merge 대상 파일의 row 1줄을 읽어서 
            if not line: #row가 없으면 해당 csv 파일 읽기 끝 
                break
            line = line.split(',')
            if len(line) > 6:            
                f2.write(','.join(line[:6]) + "," + ''.join(line[6:])) #3.읽은 row 1줄을 merge할 파일에 쓴다.

f2.close()
f.close()
        
