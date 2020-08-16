#!/usr/bin/python
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

#################################
# computation dataset from file #
#################################

dict = {}
current_year = 0
dict_prefix_year = {}
count_prefix_by_year = 0
f= open("result","r")
for i in f:
    i = i.rstrip("\n")
    if i[0].isdigit():
        if count_prefix_by_year != 0:
            dict_prefix_year[current_year] = count_prefix_by_year
            count_prefix_by_year = 0
        if i==str(0): #last line
            continue
        dict[i] = []
        current_year = i
    else:
        k = i.split("]")
        k = k[1].split(" ")
        dict[current_year].append(k[3])

        count_prefix_by_year = count_prefix_by_year + 1

#################################################
# computation distribution graph for resilience #
#################################################

sns.set(style="white", palette="muted", color_codes=True)
#rs = np.random.RandomState(500)

# Set up the matplotlib figure
f, axes = plt.subplots(3, 3, figsize=(7, 7))
#sns.despine(left=True)

# Generate a random univariate dataset
#d = rs.normal(size=100)
#print(d)

#print(dict)
y07 = dict["2007-11-01"]
y08 = dict["2008-11-01"]
y09 = dict["2009-11-01"]
y10 = dict["2010-11-01"]
y11 = dict["2011-11-01"]
y12 = dict["2012-11-01"]
y13 = dict["2013-11-01"]
y14 = dict["2014-11-01"]
y15 = dict["2015-11-01"]

sns.distplot(y07, color="b", ax=axes[0, 0], axlabel="2007")
sns.distplot(y08, color="b", ax=axes[0, 1], axlabel="2008")
sns.distplot(y09, color="b", ax=axes[0, 2], axlabel="2009")
sns.distplot(y10, color="b", ax=axes[1, 0], axlabel="2010")
sns.distplot(y11, color="b", ax=axes[1, 1], axlabel="2011")
sns.distplot(y12, color="b", ax=axes[1, 2], axlabel="2012")
sns.distplot(y13, color="b", ax=axes[2, 0], axlabel="2013")
sns.distplot(y14, color="b", ax=axes[2, 1], axlabel="2014")
sns.distplot(y15, color="b", ax=axes[2, 2], axlabel="2015")

#plt.setp(axes, yticks=[])
#plt.tight_layout()
plt.show()

########################
#computation nb prefix #
########################

year = []
nb_prefix = []
for i in sorted(dict_prefix_year):
    year.append(i)
    nb_prefix.append(dict_prefix_year[i])

# Make a fake dataset:
#height = [3, 12, 5, 18, 45]
#bars = ('A', 'B', 'C', 'D', 'E')

year = ["2007", "2008", "2009", "2010", "2011", "2012", "2013", "2014", "2015"]

height = nb_prefix
bars = year

y_pos = np.arange(len(bars))

# Create bars
plt.bar(y_pos, height)

# Create names on the x-axis
plt.xticks(y_pos, bars)

# Show graphic
plt.show()

########################
#computation AS number #
########################

year = ["2007", "2008", "2009", "2010", "2011", "2012", "2013", "2014", "2015"]
#nb_AS = [0, 0, 0, 0, 0, 0, 46171, 49346, 52900, 0, 0, 0, 0]
nb_AS = [27034, 30119, 33232, 36360, 39930, 43105, 46171, 49346, 52900]

height = nb_AS
bars = year

y_pos = np.arange(len(bars))

# Create bars
plt.bar(y_pos, height)

# Create names on the x-axis
plt.xticks(y_pos, bars)

# Show graphic
plt.show()

##################################
# computation average resilience #
##################################

year = []
avg_resilience = []
for i in sorted(dict):
    year.append(i)
    avg = 0
    for k in dict[i]:
        avg = avg + float(k)
    avg = avg/len(dict[i])
    avg_resilience.append(avg)

# Make a fake dataset:
#height = [3, 12, 5, 18, 45]
#bars = ('A', 'B', 'C', 'D', 'E')

year = ["2007", "2008", "2009", "2010", "2011", "2012", "2013", "2014", "2015"]

height = avg_resilience
bars = year

y_pos = np.arange(len(bars))

# Create bars
plt.bar(y_pos, height)

# Create names on the x-axis
plt.xticks(y_pos, bars)

# Show graphic
plt.show()
