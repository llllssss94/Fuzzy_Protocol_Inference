import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns


def get_flow(path, src_ip, dst_ip):
    data = pd.read_csv(path)
    raw_data = data.values

    print(path, "-len - ", len(raw_data))

    clean_data = []
    flows = []

    # 패킷의 전송 간격을 구함
    interval = []
    last = 0
    for line in raw_data:
        if line[2] == src_ip or line[2] == dst_ip:
            interval.append(line[1]-last)
            last = line[1]
            clean_data.append(line)

    # 패킷 평균 전송 간격
    avg = sum(interval) / len(interval)
    print(avg)

    diverge = []

    i = 0
    # 평균 전송간격보다 큰 경우 flow를 분리를 위한 인덱스 찾기
    for t in interval:
        if t >= avg:
            diverge.append(i)
        i = i + 1

    # 찾은 인덱스로 flow를 분리
    prefix = 0
    for idx in diverge:
        if idx >= len(clean_data):
            break
        flow = clean_data[prefix:idx]
        flows.append(flow)
        prefix = idx + 1

    print("## 총 ", len(flows), "개의 flow 발견")

    # 평균 인터벌
    avg_ivl = []
    # 평균 페이로드 크기
    avg_pay = []
    # 평균 패킷 수
    avg_cnt = []
    # 프로토콜 넘뻐
    pcl = []

    for flow in flows:
        last = 0
        ivl = 0
        payload = 0
        if len(flow) <= 0:
            continueLS
        for line in flow:
            ivl = ivl + (line[1]-last)
            last = line[1]
            payload = payload + line[5]

        # 값 입력
        avg_ivl.append(ivl / len(flow))
        avg_pay.append(payload / len(flow))
        avg_cnt.append(len(flow))
        if flow[0][4] == "UDP":
            pcl.append(17)
        elif flow[0][4] == "TCP":
            pcl.append(6)

    print(sum(avg_pay)/len(avg_pay))

    return (np.array([avg_ivl, avg_cnt, avg_pay, pcl])).T


if __name__ == "__main__":
    low_flow = get_flow("./data/30sec_server.csv", '10.0.0.1', '10.0.0.2')

    high_flow = get_flow("./data/1080_server.csv", '10.0.0.1', '10.0.0.2')

    chat_flow = get_flow("./data/chat_server.csv", '10.0.0.1', '10.0.0.2')

    full_data = pd.DataFrame({'interval': high_flow[:, 0], 'count': high_flow[:, 1], 'size': high_flow[:, 2], 'proto': high_flow[:, 3]})

    sns.scatterplot(x=range(len(full_data['interval'])), y=full_data['interval'])
    plt.show()
