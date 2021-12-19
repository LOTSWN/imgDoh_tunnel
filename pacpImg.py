'''
pcap可视化
'''
import os
import random

import numpy as np
import cv2 as cv

class readData():
    def __init__(self, root=".\DoHtunnel\dataset\pcaps_test", should_pad=False):
        self.root = root
        self.should_pad = should_pad
        self.pcaps = []
        num = 0
        for f in os.listdir(root):
            full_path = os.path.join(self.root, f)
            if os.path.getsize(full_path) < 500_000:
                self.pcaps.append(full_path)
        random.shuffle(self.pcaps)
        self.max_len = 40000
        for pcap in self.pcaps:
            self.max_len = max(self.max_len, os.path.getsize(pcap))
            if(self.max_len > 40_000):
                self.max_len=40000
                break

    def __len__(self):
        return len(self.pcaps)

    def getitem(self, pcapath):
        b=[]
        nums=0
        with open(pcapath, 'rb') as f:
            for i in f.read():
                b.append(int(i))
                nums+=1
                if(nums>=self.max_len):
                    break
        if self.should_pad and len(b)<self.max_len:
            b += [0] * (self.max_len - len(b))
        print(len(b))
        # image shape
        imgb=np.array(b).reshape(200,200)
        # save image
        # print(pcapath.split('\\')[6])
        pattth='.\\images\\maliciousImg5\\'+pcapath.split('\\')[6].split('.')[0]+'.png'
        cv.imwrite(pattth, imgb)  # 保存写有信息的图片


if __name__ == "__main__":
    myroot='.\DoHtunnel\dataset\MaliciousDoH-dnscat2-2'
    dataset = readData(should_pad=True,root=myroot)
    num=0
    for pcap in dataset.pcaps:
        dataset.getitem(pcap)
