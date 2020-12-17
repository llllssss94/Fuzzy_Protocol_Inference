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
    if type(target) != str:
        target = str(target)

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


def get_flow(d):
    if len(d) < 1:
        return 0
    raw_data = d.values
    keywords = extract(d=d)[1:]

    # print("len - ", len(raw_data))

    clean_data = []
    flows = []

    # 패킷의 전송 간격을 구함
    interval = []
    last = 0
    for line in raw_data:
        interval.append(line[1]-last)
        last = line[1]
        clean_data.append(line)
    # print("interval - ", len(interval))
    # 패킷 평균 전송 간격
    if len(interval) < 1:
        return 0
    avg = sum(interval) / len(interval)
    # print("avg interval - ", avg)

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

    if len(flows) < 100:
        return 0


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
            payload = payload + len(str(line[5]))

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
    return [avg_skn, avg_skl, avg_pay, avg_fsa, avg_ivl]   # [avg_ivl, avg_cnt, avg_pay, pcl]


def membership_function(data=pd.DataFrame([]), cols="", sigma=1.0):

    # find bound values from traffic flows in same traffic type data
    # find bound values from traffic flows in same traffic type data

    lbl = ""
    if cols == "CON":
        x_con = np.arange(0, 100.5, 0.5)

        conf_mal = fuzz.trapmf(x_con, [0, 20, 40, 60])
        conf_nor = fuzz.trapmf(x_con, [40, 60, 80, 100])
        """
        plt.plot(x_con, conf_mal, 'r', linewidth=1.5, label='mal')
        plt.plot(x_con, conf_nor, 'g', linewidth=1.5, label='nor')

        plt.show()
        """

        return [x_con, conf_mal, conf_nor]
    elif cols == "SKN":
        lbl = "Static Keyword Number"
    elif cols == "SKL":
        lbl = "Static Keyword Length"
    elif cols == "PSA":
        lbl = "Packet Size Average"
    elif cols == "FSA":
        lbl = "Field Size Average"
    else:
        lbl = "Packet Interval Average"

    print(data[cols].min(), "~", data[cols].max())

    chat_pia = data[cols]

    """
    # for quantile method
    # divide data
    chat_pia = chat_pia.sort_values()
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

    """
    fig, ((ax0, ax1, ax4), (ax3, ax2, ax5)) = plt.subplots(nrows=2, ncols=3, figsize=(24, 10))
    
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

    """
    ax3.plot(raw_data, low_6, 'b', linewidth=1.5, label='Low')
    ax3.plot(raw_data, match_6, 'g', linewidth=1.5, label='Match')
    ax3.plot(raw_data, high_6, 'r', linewidth=1.5, label='High')
    ax3.set_title('min/max-based gaussian')
    ax3.set_xlabel(lbl)
    ax3.set_ylabel('Estimated Membership Degree')
    ax3.legend()

    
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

    plt.show()
    """

    return [low_6, match_6, high_6, raw_data]


def make_membership(data=pd.DataFrame([]), sigma=1.0):
    mf_skn = membership_function(data=data, cols="SKN", sigma=sigma)
    mf_skl = membership_function(data=data, cols="SKL", sigma=sigma)
    mf_psa = membership_function(data=data, cols="PSA", sigma=sigma)
    mf_fsa = membership_function(data=data, cols="FSA", sigma=sigma)
    mf_pia = membership_function(data=data, cols="PIA", sigma=sigma)

    return [mf_skn, mf_skl, mf_psa, mf_fsa, mf_pia]

def fuzzy_inference_engine(skn, skl, psa, fsa, pia, mf, con_mf):
    # 4.49, 3.64, 90, 85, 250
    x1, x2, x3, x4, x5 = (skn, skl, psa, fsa, pia)  # SKN, SKL, PSA, FSA, PIA input

    try:
        skn_lo = fuzz.interp_membership(mf[0][3], mf[0][0], x1)
        skn_mt = fuzz.interp_membership(mf[0][3], mf[0][1], x1)
        skn_hi = fuzz.interp_membership(mf[0][3], mf[0][2], x1)

        skl_lo = fuzz.interp_membership(mf[1][3], mf[1][0], x2)
        skl_mt = fuzz.interp_membership(mf[1][3], mf[1][1], x2)
        skl_hi = fuzz.interp_membership(mf[1][3], mf[1][2], x2)

        psa_lo = fuzz.interp_membership(mf[2][3], mf[2][0], x3)
        psa_mt = fuzz.interp_membership(mf[2][3], mf[2][1], x3)
        psa_hi = fuzz.interp_membership(mf[2][3], mf[2][2], x3)

        fsa_lo = fuzz.interp_membership(mf[3][3], mf[3][0], x4)
        fsa_mt = fuzz.interp_membership(mf[3][3], mf[3][1], x4)
        fsa_hi = fuzz.interp_membership(mf[3][3], mf[3][2], x4)

        pia_lo = fuzz.interp_membership(mf[4][3], mf[4][0], x5)
        pia_mt = fuzz.interp_membership(mf[4][3], mf[4][1], x5)
        pia_hi = fuzz.interp_membership(mf[4][3], mf[4][2], x5)

        hi = [skn_hi, skl_hi, psa_hi, fsa_hi, pia_hi]
        mt = [skn_mt, skl_mt, psa_mt, fsa_mt, pia_mt]
        lo = [skn_lo, skl_lo, psa_lo, fsa_lo, pia_lo]

        # if pia, skl, skn, psa, fsa is match then confidence is near 90
        rule1 = reduce(lambda x, y: x * y, mt)
        con_nor = np.fmin(np.multiply(rule1, 0.99), con_mf[2])

        # if pia, skl, skn, psa, fsa is high then confidence or pia, skl, skn, psa, fsa is low is near 10
        rule2 = np.fmax(reduce(lambda x, y: x * y, hi), reduce(lambda x, y: x * y, lo))
        con_mal = np.fmin(np.multiply(rule2, 0.01), con_mf[1])

        """
        # Visualize this
        fig, ax0 = plt.subplots(figsize=(8, 8))

        con0 = np.zeros_like(con_mf[0])
        ax0.fill_between(con_mf[0], con0, con_nor, facecolor='b', alpha=0.7)
        ax0.plot(con_mf[0], con_mf[1], 'b', linewidth=0.5, linestyle='--', )
        ax0.fill_between(con_mf[0], con0, con_mal, facecolor='g', alpha=0.7)
        ax0.plot(con_mf[0], con_mf[2], 'g', linewidth=0.5, linestyle='--')
        ax0.set_title('Output membership activity')
    
        # Turn off top/right axes
        for ax in (ax0,):
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.get_xaxis().tick_bottom()
            ax.get_yaxis().tick_left()

        plt.tight_layout()

        plt.show()
     
        aggregate = np.fmax(con_mal, con_nor)
        print("CONFIDENCE(CENTROID)", fuzz.defuzz(con_mf[0], aggregate, 'centroid'))
        print("CONFIDENCE(MEAN)", fuzz.defuzz(con_mf[0], aggregate, 'mom'))
        print("CONFIDENCE(BISECTOR)", fuzz.defuzz(con_mf[0], aggregate, 'bisector'))
        print("CONFIDENCE(MIN)", fuzz.defuzz(con_mf[0], aggregate, 'som'))
        print("CONFIDENCE(MAX)", fuzz.defuzz(con_mf[0], aggregate, 'lom'))
        """

        # WEIGHTED AVERAGE DEFUZZIFICATION METHOD
        cf_1 = fuzz.defuzz(con_mf[0], con_mal, 'centroid')
        cf_2 = fuzz.defuzz(con_mf[0], con_nor, 'centroid')

        confidence = np.divide(max(con_mal) * cf_1 + max(con_nor) * cf_2, max(con_mal) + max(con_nor))
        #print("CONFIDENCE(WEIGHTED AVERAGE)", confidence)

        # conf_activation = fuzz.interp_membership(con_mf[0], np.fmax(cf_1, cf_2), confidence)

        """
        fig1, ax1 = plt.subplots(figsize=(8, 8))

        ax1.plot(con_mf[0], con_mf[1], 'b', linewidth=0.5, linestyle='--', )
        ax1.plot(con_mf[0], con_mf[2], 'g', linewidth=0.5, linestyle='--')
        ax1.fill_between(con_mf[0], con0, aggregate, facecolor='Orange', alpha=0.7)
        ax1.plot([confidence, confidence], [0, conf_activation], 'k', linewidth=1.5, alpha=0.9)
        ax1.set_title('Aggregated membership and result (line)')

        # Turn off top/right axes
        for ax in (ax1,):
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.get_xaxis().tick_bottom()
            ax.get_yaxis().tick_left()

        plt.tight_layout()
        plt.show()
        """
    except:
        return 0

    return confidence


# for preprocessing only
def data_process(path):
    nm = path.split('/')[3]
    print(nm)
    data = pd.read_csv(path)
    src_set = set(data["ip.src"])

    f = open("./processed/VPN/" + nm + "_processed.csv" ,'w')
    f.write(','.join(["SKN", "SKL", "PSA", "FSA", "PIA"]) + "\n")

    # rl = np.array([])

    for ips in src_set:
        if type(ips) == float:
            continue
        dst_set = set(data[data["ip.src"] == ips]["ip.dst"])
        for ipd in dst_set:
            data_part = data[data["ip.src"] == ips]
            data_part = data_part[data_part["ip.dst"] == ipd]
            tmp = get_flow(data_part)
            if tmp != 0:
                print("add")
                tmp = np.array(tmp).transpose()
                for line in tmp:
                    f.write(','.join(map(str, line)) + "\n")
                """
                if len(rl) <= 1:
                    rl = tmp
                else:
                    rl = np.hstack((rl, tmp))
                """
    f.close()
    #rl = pd.DataFrame(rl.transpose(), columns=['ivl', 'cnt', 'pay', 'pcl'])
    #rl.to_csv("./processed/nonVPN/" + nm + "_processed.csv", index=False)

def do_inferece(nm = 0, thresh = 65, sigma = 1):

    target_nm = nm
    class_nm = ['Chat', 'Email', 'FileTransfer', 'P2P', 'Streaming', 'VoIP']

    import time
    start = time.time() # learning start

    mf_list = []
    conmf_list = []

    oposit_data = []

    for i in range(len(class_nm)):
        target_data = pd.read_csv("./processed/" + class_nm[i] + "_processed.csv") # , columns=["SKN", "SKL", "PSA", "FSA", "PIA"]
        mf_list.append(make_membership(data=target_data, sigma=sigma))
        conmf_list.append(membership_function(data=target_data, cols="CON"))

    end = time.time()   # learning end
    print(end - start)

    for i in range(len(class_nm)):
        if i == target_nm:
            target_data = pd.read_csv("./processed/" + class_nm[i] + "_processed.csv").values
            print(target_data)
        else:
            oposit_data.extend(pd.read_csv("./processed/" + class_nm[i] + "_processed.csv").values)
    print(len(oposit_data))

    target_data = pd.DataFrame(target_data, columns=["SKN", "SKL", "PSA", "FSA", "PIA"])
    oposit_data = pd.DataFrame(oposit_data, columns=["SKN", "SKL", "PSA", "FSA", "PIA"])


    print("\n" + class_nm[target_nm] + "Flow ---------------------------------------------------------")
    target_count = 0
    target_conf = []
    target_len = target_data.values.__len__()
    for flow in target_data.values:
        ridx = 0
        conf = 0
        for idx in range(len(mf_list)):
            tmp = fuzzy_inference_engine(flow[0], flow[1], flow[2], flow[3], flow[4], mf_list[idx], conmf_list[idx])
            if conf < tmp:
                conf = tmp
                ridx = idx
        if ridx == target_nm:
            target_count += 1
            target_conf.append(conf)

    print("Declare - ", target_count)
    print("Rate - ", target_count / target_len)
    print("Confidence - ", np.average(target_conf))

    print("\nOposit Flow ---------------------------------------------------------")
    oposit_count = 0
    oposit_conf = []
    oposit_len = oposit_data.values.__len__()
    for flow in oposit_data.values:
        ridx = 0
        conf = 0
        for idx in range(len(mf_list)):
            tmp = fuzzy_inference_engine(flow[0], flow[1], flow[2], flow[3], flow[4], mf_list[idx], conmf_list[idx])
            if conf < tmp:
                conf = tmp
                ridx = idx
        if ridx == target_nm:
            oposit_count += 1
            oposit_conf.append(conf)


    print("Declare - ", oposit_count)
    print("Rate - ", oposit_count / oposit_len)
    print("Confidence - ", np.average(oposit_conf))


    Precision = target_count / (target_count + oposit_count)
    Recall = target_count / target_len
    Accuracy = (target_count + (oposit_len - oposit_count)) / (target_len + oposit_len)
    F1_Score = 2 * ((Precision * Recall) / (Precision + Recall))
    print("PP - ", (target_count / target_len))
    print("FP - ", (oposit_count / oposit_len))
    print("Precision - ", Precision)
    print("Recall - ", Recall)
    print("Accuracy - ", Accuracy)
    print("F1_Score - ", F1_Score)

    f = open("./result/" + class_nm[target_nm] + "_" + str(thresh) + ".txt", "a+")
    f.write("PP - " + str((target_count / target_len)) + "\n")
    f.write("FP - " + str((oposit_count / oposit_len)) + "\n")
    f.write("Precision - " + str(Precision) + "\n")
    f.write("Recall - " + str(Recall) + "\n")
    f.write("Accuracy - " + str(Accuracy) + "\n")
    f.write("F1_Score - " + str(F1_Score) + "\n")

    f.close()

    fig1, ax1 = plt.subplots(figsize=(8, 4))
    ax1.plot(np.arange(0, target_conf.__len__(), step=1), target_conf, 'b')
    ax1.set_title(class_nm[target_nm] + 'Traffic Confidence')
    ax1.set_xlabel('Time')
    ax1.set_ylabel('Estimated Confidence')

    plt.show()

    fig2, ax2 = plt.subplots(figsize=(8, 4))
    ax2.plot(np.arange(0, oposit_conf.__len__(), step=1), oposit_conf, 'g')
    ax2.set_title('Miss Classified Traffic Confidence')
    ax2.set_xlabel('Time')
    ax2.set_ylabel('Estimated confidence')

    plt.show()


if __name__ == "__main__":
    """
    low_flow = pd.DataFrame(get_flow("./data/30sec_server.csv", '10.0.0.1', '10.0.0.2'),
                            columns=["SKN", "SKL", "PSA", "FSA", "PIA"])

    print(low_flow)

    
    # for origin data only
    low_flow = get_flow("./30sec_server.csv", '10.0.0.1', '10.0.0.2')
    high_flow = get_flow("./Datasets/nonVPN/Chat/merge.csv", '131.202.240.87', '10.0.0.2')
    chat_flow = get_flow("./chat_server.csv", '10.0.0.1', '10.0.0.2')
    """


    #data_process("./Datasets/VPN/Chat/merge.csv")
    #data_process("./Datasets/VPN/Email/merge.csv")
    #data_process("./Datasets/VPN/FileTransfer/merge.csv")
    #data_process("./Datasets/VPN/P2P/merge.csv")
    data_process("./Datasets/VPN/Streaming/merge.csv")
    #data_process("./Datasets/VPN/VoIP/merge.csv")


    #do_inferece(nm = 0, thresh = 69) # Chat
    #do_inferece(nm = 1, thresh = 68) # Email
    #do_inferece(nm = 2, thresh = 70, sigma=-2) # File
    #do_inferece(nm = 3, thresh = 69) # P2P
    #do_inferece(nm = 4, thresh = 69) # Streaming
    #do_inferece(nm = 5, thresh = 70) # VoIP





    """
    high_flow = pd.DataFrame(get_flow("./data/1080_server.csv", '10.0.0.1', '10.0.0.2'),
                             columns=["SKN", "SKL", "PSA", "FSA", "PIA"])

    chat_flow = pd.DataFrame(get_flow("./data/chat_server.csv", '10.0.0.1', '10.0.0.2'),
                             columns=["SKN", "SKL", "PSA", "FSA", "PIA"])

    low_flow_part = low_flow

    mf = make_membership(data=low_flow_part, sigma=10)
    con_mf = membership_function(data=low_flow_part, cols="CON")

    # Experiment
    print("\nChatting Flow ---------------------------------------------------------")
    chat_count = 0
    chat_conf = []
    chat_len = chat_flow.values.__len__()
    for flow in chat_flow.values:
        conf = fuzzy_inference_engine(flow[0], flow[1], flow[2], flow[3], flow[4], mf, con_mf)
        if conf > 0:
            chat_conf.append(conf)
            if conf > 65:
                chat_count += 1
    print("Declare - ", chat_count)
    print("Rate - ", chat_count/chat_len)
    print("Confidence - ", np.average(chat_conf))

    print("\nLow Flow ---------------------------------------------------------")
    low_count = 0
    low_conf = []
    low_len = low_flow.values.__len__()
    for flow in low_flow.values:
        conf = fuzzy_inference_engine(flow[0], flow[1], flow[2], flow[3], flow[4], mf, con_mf)
        if conf > 0:
            low_conf.append(conf)
            if conf > 65:
                low_count += 1
    print("Declare - ", low_count)
    print("Rate - ", low_count / low_len)
    print("Confidence - ", np.average(low_conf))

    print("\nHigh Flow ---------------------------------------------------------")
    high_count = 0
    high_conf = []
    high_len = high_flow.values.__len__()
    for flow in high_flow.values:
        conf = fuzzy_inference_engine(flow[0], flow[1], flow[2], flow[3], flow[4], mf, con_mf)
        if conf > 0:
            high_conf.append(conf)
            if conf > 65:
                high_count += 1
    print("Declare - ", high_count)
    print("Rate - ", high_count / high_len)
    print("Confidence - ", np.average(high_conf))

    f = open("10_high_conf.txt", "a+")

    for line in high_conf:
        f.write(str(line))
        f.write(",")

    f.close()

    print("정탐률 - ", low_count / low_len)
    print("오탐률 - ", (chat_count + high_count) / (chat_len + high_len))
    """
    """ threshold transition
    fp_rate = []
    threshold_list = np.linspace(50, 69.7, num=340)  # 60, 69.7, num=97

    for thr in threshold_list:
        chat_count = 0
        for cc in chat_conf:
            if cc > thr:
                chat_count += 1

        low_count = 0
        for lc in low_conf:
            if lc > thr:
                low_count += 1

        high_count = 0
        for hc in high_conf:
            if hc > thr:
                high_count += 1

        fp_rate.append((chat_count + high_count) / (chat_len + high_len))
        print("정탐률 - ", low_count / low_len)
        print("오탐률 - ", (chat_count + high_count) / (chat_len + high_len))
    """
    """
    fig1, ax1 = plt.subplots(figsize=(8, 4))
    ax1.plot(np.arange(0, high_conf.__len__(), step=1), high_conf, 'b')
    ax1.set_title('High-intensity streaming traffic')
    ax1.set_xlabel('Time')
    ax1.set_ylabel('Estimated Confidence')

    plt.show()

    fig2, ax2 = plt.subplots(figsize=(8, 4))
    ax2.plot(np.arange(0, low_conf.__len__(), step=1), low_conf, 'g')
    ax2.set_title('Low-intensity streaming traffic')
    ax2.set_xlabel('Time')
    ax2.set_ylabel('Estimated confidence')

    plt.show()

    fig3, ax3 = plt.subplots(figsize=(8, 4))
    ax3.plot(np.arange(0, chat_conf.__len__(), step=1), chat_conf, 'r')
    ax3.set_title('Text (TCP Chatting) traffic')
    ax3.set_xlabel('Time')
    ax3.set_ylabel('Estimated confidence')

    plt.show()
    """
    """

    fig4, ax4 = plt.subplots(figsize=(8, 6))
    ax4.plot(threshold_list, fp_rate, 'c')
    ax4.set_title('FP-Rate Transition')
    ax4.set_xlabel('threshold')
    ax4.set_ylabel('False-Positive Rate')

    plt.show()
    """

    exit(0)
