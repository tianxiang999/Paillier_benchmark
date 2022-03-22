from cgi import test
import random
from sys import getsizeof

size = 128*1024
#length = 8byte(float) * size = 8*128*1024 = 1024*1024B = 1MB
nums1 = [random.random() for _ in range(size)]
n2 = []
print(getsizeof(nums1[0]))

test_size = [128,12800,128*1024]
for i in test_size:
    print(i)
