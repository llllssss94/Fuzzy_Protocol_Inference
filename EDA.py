import pandas as pd
import numpy as np
from apriori import extract
import skfuzzy as fuzz
import matplotlib.pyplot as plt
from functools import reduce


def dynamic_cal(key, target):   # calculate PF for each packet
    kl = key
    SKL = 0
    SKN = 0

    for k in kl:
        offset = target.find(k)
        if offset < 0:  # If there is no keyword in target,
            continue

        if len(k) <= 0:  # Noise canceling
            continue

        SKL += len(k)

        """
        if len(rule) > 0:
            rule.append({"len": offset - rule[i - 1]["len"], "type": i})    # dynamic field size
            rule.append({"len": offset + len(k) + 1, "type": k})    # keyword end position
        else:
            rule.append({"len": offset + len(k) + 1, "type": k})    # keyword end position
        """
        SKN += 1

    if SKL == 0 or SKN == 0:
        return 0, 0, 0

    SKL = SKL/SKN

    return SKL, SKN, len(target) - SKL


def get_flow(path, src_ip, dst_ip):
    data = pd.read_csv(path)
    raw_data = data.values
    keywords = extract(i_url=path)[1:]

    print(path, "- len - ", len(raw_data))

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

    # 평균 인터벌  use
    avg_ivl = []
    # static keyword number average
    avg_skn = []
    # static keyword length average
    avg_skl = []
    # field size average
    avg_fsa = []
    # 평균 페이로드 크기 use
    avg_pay = []

    """
    # 평균 패킷 수
    avg_cnt = []
    # 프로토콜 넘뻐
    pcl = []
    """

    for flow in flows:
        last = 0
        ivl = 0
        payload = 0
        skl = 0
        skn = 0
        fsa = 0
        if len(flow) <= 0:
            continue
        for line in flow:
            tskl, tskn, tfsa = dynamic_cal(keywords, line[6])
            skl += tskl
            skn += tskn
            fsa += tfsa
            ivl = ivl + (line[1]-last)
            last = line[1]
            payload = payload + line[5]

        # 값 입력
        avg_ivl.append(ivl / len(flow))
        avg_pay.append(payload / len(flow))
        avg_skl.append(skl / len(flow))
        avg_skn.append(skn / len(flow))
        avg_fsa.append(fsa / len(flow))
        """
        avg_cnt.append(len(flow))
        if flow[0][4] == "UDP":
            pcl.append(17)
        elif flow[0][4] == "TCP":
            pcl.append(6)
        """
    print(sum(avg_pay)/len(avg_pay))

    return (np.array([avg_skn, avg_skl, avg_pay, avg_fsa, avg_ivl])).T   # [avg_ivl, avg_cnt, avg_pay, pcl]


def membership_fucntion(data=pd.DataFrame([]), cols="", sigma=1.0):

    # find bound values from traffic flows in same traffic type data
    # find bound values from traffic flows in same traffic type data
    print(data[cols].min(), "~", data[cols].max())

    lbl = ""

    if cols == "SKN":
        lbl = "Static Keyword Number"
    elif cols == "SKL":
        lbl = "Static Keyword Length"
    elif cols == "PSA":
        lbl = "Packet Size Average"
    elif cols == "FSA":
        lbl = "Field Size Average"
    else:
        lbl = "Packet Interval Average"

    chat_pia = data[cols]

    """ for quantile method
    # divide data
    low_data = chat_pia[chat_pia <= np.quantile(chat_pia, 0.25)].to_numpy()  # 1-quartile
    match_data = chat_pia[chat_pia <= np.quantile(chat_pia, 0.75)][chat_pia >= np.quantile(chat_pia, 0.25)].to_numpy()
    high_data = chat_pia[chat_pia > np.quantile(chat_pia, 0.75)].to_numpy()  # 3-quartile
    """

    min = chat_pia.min()
    mean = chat_pia.mean()
    median = chat_pia.median()
    max = chat_pia.max()
    st = chat_pia.std()

    chat_pia = chat_pia.append(pd.Series([min - (st * sigma), max + (st * sigma)]))

    raw_data = (chat_pia.sort_values()).to_numpy()

    fig, ((ax0, ax1, ax4), (ax3, ax2, ax5)) = plt.subplots(nrows=2, ncols=3, figsize=(24, 10))

    """
    # Gaussian with 1-quantile average 3-quantile
    low = fuzz.gaussmf(low_data, low_data.mean(), low_data.std())
    match = fuzz.gaussmf(match_data, match_data.mean(), match_data.std())
    high = fuzz.gaussmf(high_data, high_data.mean(), high_data.std())

    ax0.plot(low_data, low, 'b', linewidth=1.5, label='Low')
    ax0.plot(match_data, match, 'g', linewidth=1.5, label='Match')
    ax0.plot(high_data, high, 'r', linewidth=1.5, label='High')
    ax0.set_title('quartile-based gaussian')
    ax0.set_xlabel(lbl)
    ax0.set_ylabel('Estimated Membership Degree')
    ax0.legend()
    """

    # Gaussian with min average max
    low_6 = fuzz.gaussmf(raw_data, min, st)
    match_6 = fuzz.gaussmf(raw_data, mean, st)
    high_6 = fuzz.gaussmf(raw_data, max, st)

    ax3.plot(raw_data, low_6, 'b', linewidth=1.5, label='Low')
    ax3.plot(raw_data, match_6, 'g', linewidth=1.5, label='Match')
    ax3.plot(raw_data, high_6, 'r', linewidth=1.5, label='High')
    ax3.set_title('min/max-based gaussian')
    ax3.set_xlabel(lbl)
    ax3.set_ylabel('Estimated Membership Degree')
    ax3.legend()

    """
    # Triangular with min, max and average
    low_2 = fuzz.trimf(raw_data, [min, min, mean])
    match_2 = fuzz.trimf(raw_data, [min, mean, max])  # average
    high_2 = fuzz.trimf(raw_data, [mean, max, max])

    ax1.plot(raw_data, low_2, 'b', linewidth=1.5, label='Low')
    ax1.plot(raw_data, match_2, 'g', linewidth=1.5, label='Match')
    ax1.plot(raw_data, high_2, 'r', linewidth=1.5, label='High')
    ax1.set_title('average triangular')
    ax1.set_xlabel(lbl)
    ax1.set_ylabel('Estimated Membership Degree')
    ax1.legend()

    # Triangular with min, max and median
    low_3 = fuzz.trimf(raw_data, [min, min, median])
    match_3 = fuzz.trimf(raw_data, [min, median, max])  # average
    high_3 = fuzz.trimf(raw_data, [median, max, max])

    ax2.plot(raw_data, low_3, 'b', linewidth=1.5, label='Low')
    ax2.plot(raw_data, match_3, 'g', linewidth=1.5, label='Match')
    ax2.plot(raw_data, high_3, 'r', linewidth=1.5, label='High')
    ax2.set_title('median triangular')
    ax2.set_xlabel(lbl)
    ax2.set_ylabel('Estimated Membership Degree')
    ax2.legend()

    # Trapezoidal with min, max and mean
    low_l = sorted([min * 0.8, min, min * 1.2, mean])
    match_l = sorted([min, mean * 0.8, mean * 1.2, max])
    high_l = sorted([mean, max * 0.8, max, max * 1.2])

    low_4 = fuzz.trapmf(raw_data, low_l)
    match_4 = fuzz.trapmf(raw_data, match_l)  # average
    high_4 = fuzz.trapmf(raw_data, high_l)

    ax4.plot(raw_data, low_4, 'b', linewidth=1.5, label='Low')
    ax4.plot(raw_data, match_4, 'g', linewidth=1.5, label='Match')
    ax4.plot(raw_data, high_4, 'r', linewidth=1.5, label='High')
    ax4.set_title('mean Trapezoidal')
    ax4.set_xlabel(lbl)
    ax4.set_ylabel('Estimated Membership Degree')
    ax4.legend()

    # Trapezoidal with min, max and median
    low_l = sorted([min * 0.8, min, min * 1.2, median])
    match_l = sorted([min, median * 0.8, median * 1.2, max])
    high_l = sorted([median, max * 0.8, max, max * 1.2])

    low_5 = fuzz.trapmf(raw_data, low_l)
    match_5 = fuzz.trapmf(raw_data, match_l)  # average
    high_5 = fuzz.trapmf(raw_data, high_l)

    ax5.plot(raw_data, low_5, 'b', linewidth=1.5, label='Low')
    ax5.plot(raw_data, match_5, 'g', linewidth=1.5, label='Match')
    ax5.plot(raw_data, high_5, 'r', linewidth=1.5, label='High')
    ax5.set_title('median Trapezoidal')
    ax5.set_xlabel(lbl)
    ax5.set_ylabel('Estimated Membership Degree')
    ax5.legend()
    """
    x_con = np.arange(0, 100.5, 0.5)

    conf_mal = fuzz.trapmf(x_con, [0, 0, 10, 100])
    conf_nor = fuzz.trapmf(x_con, [0, 90, 100, 100])

    plt.plot(x_con, conf_mal, 'r', linewidth=1.5, label='mal')
    plt.plot(x_con, conf_nor, 'g', linewidth=1.5, label='nor')

    plt.show()

    return [low_6, match_6, high_6, raw_data, [conf_mal, conf_nor]]


def fuzzifier(data=pd.DataFrame([]), sigma=1.0):
    mf_skn = membership_fucntion(data=chat_flow, cols="SKN", sigma=10)
    mf_skl = membership_fucntion(data=chat_flow, cols="SKL", sigma=10)
    mf_psa = membership_fucntion(data=chat_flow, cols="PSA", sigma=10)
    mf_fsa = membership_fucntion(data=chat_flow, cols="FSA", sigma=10)
    mf_pia = membership_fucntion(data=chat_flow, cols="PIA", sigma=10)

    return [mf_skn, mf_skl, mf_psa, mf_fsa, mf_pia]

def defuzzifier(mf, value):
    mf



    confidence = 0

    return confidence


if __name__ == "__main__":
    low_flow = pd.DataFrame(get_flow("./data/30sec_server.csv", '10.0.0.1', '10.0.0.2'),
                            columns=["SKN", "SKL", "PSA", "FSA", "PIA"])

    high_flow = pd.DataFrame(get_flow("./data/1080_server.csv", '10.0.0.1', '10.0.0.2'),
                             columns=["SKN", "SKL", "PSA", "FSA", "PIA"])

    chat_flow = pd.DataFrame(get_flow("./data/chat_server.csv", '10.0.0.1', '10.0.0.2'),
                             columns=["SKN", "SKL", "PSA", "FSA", "PIA"])

    mf = fuzzifier(data=chat_flow, sigma=10)

    """
    confidence['malicious'] = fuzz.trimf(confidence.universe, [])
    confidence['mboundary'] = 
    confidence['match'] = 
    """

    # x1, x2, x3, x4, x5 =

    # calculate membership degree
    md = [fuzz.interp_membership(mf[0][3], mf[0][1], 4.7),
          fuzz.interp_membership(mf[1][3], mf[1][1], 3.67),
          fuzz.interp_membership(mf[2][3], mf[2][1], 120),
          fuzz.interp_membership(mf[3][3], mf[3][1], 85),
          fuzz.interp_membership(mf[4][3], mf[4][1], 300)]

    print(md)

    rule1 = reduce(lambda x, y: x * y, md)

    defuzzifier(mf[5], rule1)

    exit(0)


"""
    sns.scatterplot(x=range(len(full_data['interval'])), y=full_data['interval'])
    plt.show()
"""