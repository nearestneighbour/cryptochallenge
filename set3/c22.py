import time

from c21 import mt19973_rng

def get_timestamp_seed(x):
    now = time.gmtime()
    start = int(time.mktime(time.struct_time((now[0],now[1],now[2],0,0,0,0,0,0))))
    end = int(time.mktime(time.struct_time((now[0],now[1],now[2]+1,0,0,0,0,0,0))))
    for t in range(start, end):
        if mt19973_rng(t).rand() == x:
            return t
    raise Exception("Number not generated today")

def let_rng_run():
    ts_secret = []
    x = []
    seed = []
    for i in range(10):
        ts_secret += [int(time.time())]
        x += [mt19973_rng(ts_secret[-1]).rand()]
        time.sleep(2)
        print(i)
    return x, ts_secret

def main():
    x, ts_secret = let_rng_run()
    seeds = [get_timestamp_seed(i) for i in x]
    print(ts_secret)
    print(seeds)
