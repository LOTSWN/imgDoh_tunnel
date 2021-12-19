import tensorflow as tf
import numpy as np
from tensorflow import keras

def getitem(pcapath):
    b = []
    nums = 0
    with open(pcapath, 'rb') as f:
        for i in f.read():
            b.append(int(i) / 255)
            nums += 1
            if (nums >= 30000):
                break
    if  len(b) < 30000:
        b += [0] * ( 30000 - len(b))

    b = np.expand_dims(b, axis=1)
    b = np.expand_dims(b, axis=0)
    return tf.constant(b)

def myPredict(inpath):
    new_model = keras.models.load_model('.\\save_model1')
    DEFAULT_FUNCTION_KEY = "my_predict"
    inference_func = new_model.signatures[DEFAULT_FUNCTION_KEY]
    pcap=getitem(inpath)
    endans=tf.argmax(inference_func(pcap)['output_0'], axis=1)
    if(endans.numpy()[0] == 1):
        print("is doh!")
    else:
        print("not doh!")

if __name__=='__main__':
    #路径修改
    myPredict('.\\dataset\\doh_2.pcap')
