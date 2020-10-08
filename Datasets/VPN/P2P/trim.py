
f = open("merge_.csv", 'r')
f2 = open("merge.csv", 'w')

lines = [x.split(',') for x in f.readlines()]

for i in range(len(lines)):
    if len(lines[i]) != 6:
        continue
    f2.write(','.join(lines[i]))

f.close()
f2.close()
