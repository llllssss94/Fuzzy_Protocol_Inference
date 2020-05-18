import numpy as np
import pandas as pd
# 직접 구현


def swunch(s1, s2):
    x = len(s1) + 1  # keyword
    y = len(s2) + 1  # target

    mtx = np.zeros((x, y))  # similarity score matrix

    xi = 0
    score = 0
    for yi in range(0, y - 1):
        print(xi, yi)
        if s1[xi] == s2[yi]:
            score += 1
            mtx[xi+1][yi+1] = score
            xi = xi+1
            if xi > x - 1:
                xi = x - 1
        else:
            mtx[xi][yi+1] = score

    # is it necessary?
    mtx = mtx.transpose()
    for line in mtx:
        for i in range(0, len(line)):
            if line[i] > 0:
                line[i:] = line[i]
                break
            else:
                line[i] = i
    mtx = mtx.transpose()

    print(pd.DataFrame(mtx))


if __name__ == "__main__":
    swunch("GET / HTTP/1.0", "GET /index.html HTTP/1.0")
    exit(0)
