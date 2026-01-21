import pandas as pd

df = pd.read_csv("rsu_rx_trace.csv")
df["sender"] = df["sender"].astype(str)

counts = df.groupby("sender").size().sort_values(ascending=False)
print(counts.head(20))

def keep_steady(g):
    idx = g.index[g["rxOk"] == 1]
    if len(idx)==0: 
        return g.iloc[0:0]
    return g.loc[idx[0]:]

df_steady = df.sort_values(["sender","seq"]).groupby("sender", group_keys=False).apply(keep_steady)
counts2 = df_steady.groupby("sender").size().sort_values(ascending=False)
print(counts2.head(20))
