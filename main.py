import skfuzzy as fuzz
import numpy as np
import matplotlib.pylab as plt

x = np.array([[2, 3, 1, 2], [2, 1, 1, 0]])

n_sample, n_features = x.shape

center, mem, _, _, _, _, _ = fuzz.cmeans(x.T, 2, 2.0, error=1e-5, maxiter=200)

delta = np.zeros([2, n_features])

for i in range(2):
    d = (x - center[i, :]) **2
    print(d)

