#from typing import List

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
import dpkt
import pyshark
import math

global label
global d
global dst_port
global src_port
global ftuple
global root
global r
global port;global ports
global centroids;global online
global apps;global count
global c_labels
#filepath= 'C:/Users/Zaffar Iqbal Mir/Downloads/http.pcap'
filepath2= 'C:/Users/Zaffar Iqbal Mir/Documents/cap2.pcap'

#filepath='C:/Users/Zaffar Iqbal Mir/Downloads/ftpcaptured.pcap'

class Node:
    sp='0'
    dp='0';sip='0';dip='0';c='0'
    p1=0;p2=0;p3=0;p4=0
    left=None;right=None;pro='n';bck=None
    def __init__(self,key):
        self.sp=key[0]
        self.dp=key[1]
        self.sip=key[2]
        self.dip=key[3]
        self.c=1
        self.left= None
        self.right =None
        self.p1=key[4]
        self.p2=0;self.p3=0;self.p4=0;self.pro='nil'

apps={'NNTP':[],'POP':[], 'FTP':[],'SSH':[],'HTTP':[],'BITTORRENT':[],'TLS':[],'SMTP':[],'TELNET':[],'RTMP':[], 'SSL': [],'TCP':[], 'DATA':[],'nil':[],'MYSQL':[],'URLENCODED-FORM':[] }         #to save the first 5 packets of the connections
count={'NNTP':[],'POP':[],'FTP':[],'SSH':[],'HTTP':[],'BITTORRENT':[],'TLS':[], 'SMTP':[],'TELNET':[],'RTMP':[], 'SSL':[], 'TCP':[],'DATA':[],'nil':[],'MYSQL':[],'URLENCODED-FORM':[] }     #to save the no. of connections in each
c_labels= {'0':[],'1':[], '2':[], '3':[],'4':[],'5':[],'6':[],'7':[],'8':[],'9':[],'10':[],'11':[],'12':[]}      #cluster labels, which app is assoc with each centroid
d={'a':[],'b':[],'c':[],'x':[],'y':[]}
ports={'NNTP':[],'POP':[], 'FTP':[],'SSH':[],'HTTP':[],'BITTORRENT':[],'TLS':[], 'SMTP':[],'TELNET':[],'RTMP':[], 'SSL':[],'TCP':[], 'DATA':[],'nil':[],'MYSQL':[],'URLENCODED-FORM':[] }         #to save the first 5 packets of the connections
port={'NNTP':[],'POP':[], 'FTP':[],'SSH':[], 'HTTP':[],'BITTORRENT':[],'TLS':[], 'SMTP':[],'TELNET':[],'RTMP':[], 'SSL':[],'TCP':[], 'DATA':[],'nil':[],'MYSQL':[],'URLENCODED-FORM':[] }         #to save the first 5 packets of the connections

well_known_p=[21,22,80,110, 119, 443]
p2p=list(range(6881,6889))
t=[66,58,54,54,122]
p=np.array(t)
global sip;global dip;global sp;global dp;global proto

def minValueNode(node):
    current = node
    while current.left != None:
        current = current.left
    return current

def inorder(root):
    if root != None:
        inorder(root.left)
        print(root.sp,"(", root.dp, root.p1 , root.p2, root.p3, root.p4,root.pro, ")",end = " ")
        inorder(root.right)

def insert(node, key):                      #node points to the root of the BST, fxn inserts new connection in BST
        if node==None:          #for root of the tree
            k = Node(key)
            return k

        if key[0] < node.sp:
                    #print(node.sp, "<")
                    nod = insert(node.left, key)
                    node.left = nod
                    nod.bck=node
                    #print(node.left.sp)
        elif key[0] > node.sp:
                    #print(node.sp, " >")
                    nod= insert(node.right, key)
                    node.right = nod
                    nod.bck=node
                    #print(node.right.sp,nod.bck)
        elif key[0] == node.sp:
            if(key[1]> node.dp):
                nod = insert(node.right, key)
                node.right = nod
                print(node.right)
            elif key[1] < node.dp:
                nod = insert(node.left,key)
                node.left = nod
                print(node.left)

        return node

def insert2(node, key):
  #while(node):
        # if (key[0]+key[1] == node.sp+node.dp):
  if(node!=None):
    if (key[0] == node.sp):  # or key[0]== node.dp):
        #print("match found", node.sip, node.dip,node.c)
        if (key[1] == node.dp):
          if((key[2] == node.sip and key[3] == node.dip) or (key[2]==node.dip and key[3]== node.sip)):
            if node.c == 1:
                node.p2 = key[4]
                node.c += 1
                #print("p2  and c is", node.p1, node.c)
            elif node.c == 2:
                node.p3 = key[4]
                node.c += 1
                #print("p3 is", node.c)
            elif node.c == 3:
                node.p4 = key[4]
                node.c += 1

                pr=key[5]
                node.pro=pr
                if pr =='JSON':
                    node.pro = 'HTTP'
                elif pr =='FTP-DATA' or pr == 'DATA':
                    node.pro = 'FTP'
            elif node.c == 4:  # extract all the 5 packet sizes from the class obj. to the app.
                if node.pro == 'TCP':
                    node.pro= key[5]
                    #print(node.pro,key[5])
                apps["%s" % node.pro].append(node.p1)
                apps["%s" % node.pro].append(node.p2)
                apps["%s" % node.pro].append(node.p3)
                apps["%s" % node.pro].append(node.p4)
                apps["%s" % node.pro].append(key[4])
                ports["%s"% node.pro].append(node.dp)
                #print(apps)
                node.c += 1

            elif node.c == 5:
                return node
        if key[1] < node.dp:
            if (node.left != None):
                node.left = insert2(node.left, key)

        elif key[1] > node.dp:
            if (node.right != None):
                node.right = insert2(node.right, key)
        return node
    elif key[0] > node.sp:
        #print(node.sp, ">",key[0])
        if (node.right != None):
            node.right = insert2(node.right, key)
        else:
            return node
    elif(key[0] < node.sp):
        #print("<", key[0])
        if (node.left != None):
            node.left = insert2(node.left, key)
        else:
            return node
    return node


def fxn(root):
    root2 = root            #root of the BST
    #filepath="C:\Users\Zaffar Iqbal Mir\Downloads\ourr.pcap"
    cap = pyshark.FileCapture(filepath)
    #cap.set_debug()
    f = open(filepath, "rb", buffering=0)                     #for checking SYN flag=> new connection
    pcap = dpkt.pcap.Reader(f)
    SYN = 0x02
    ACK = 0x10
    try:
      for num, (ts, buff) in enumerate(pcap):
        #print(num)
        if int(num) == 4030:
            print(">4030")
            return root2
        eth = dpkt.ethernet.Ethernet(buff)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:                       #) or (eth.type != dpkt.ethernet.ETH_TYPE_IP6))
            #print("c1")
            continue
        ip = eth.data
        #print(ip)
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            #print("c2")
            continue
        tcp = ip.data
        if cap[num].highest_layer == 'ARP':
            print(num,"ARP")
            continue
        if (tcp.flags & dpkt.tcp.TH_CWR):
            #print("c3")
            continue
        if (tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK):       #SYN+ACK => second packet, not to be mislead with a new conn.
        #if((cap[num]['tcp'].flags & SYN ) and (cap[num]['tcp'].flags & ACK)):
                sp = cap[num].tcp.srcport
                dp = cap[num].tcp.dstport
                sip = cap[num].ip.src
                dip = cap[num].ip.dst
                l= cap[num].length
                p= cap[num].highest_layer
                #print(sp,dp)
                if (int(sp) > int(dp)):                     #in order to standardise the comparison between node.sp and current flow's sp, and not its dp.
                    #print("sp>dp")
                    root2=insert2(root2,[sp,dp,sip,dip,l,p])
                else:
                    #print("sp<dp")
                    root2=insert2(root2,[dp,sp,sip,dip,l,p])

        elif (tcp.flags & dpkt.tcp.TH_SYN):
        #elif (cap[num]['tcp'].flags and SYN):
            #print("found syn")
            #print(num)
            if hasattr(cap[num], 'tcp'):
                sp= cap[num].tcp.srcport
                dp= cap[num].tcp.dstport

            sip=cap[num].ip.src
            dip=cap[num].ip.dst
            l=cap[num].length
            root2 = insert(root2, [sp, dp, sip, dip, l])            #inserts new connection in the bst

        else:
                if hasattr(cap[num], 'tcp'):
                        sp = cap[num].tcp.srcport
                        dp = cap[num].tcp.dstport
                        sip = cap[num].ip.src
                        dip = cap[num].ip.dst
                        p=  cap[num].highest_layer
                        l = cap[num].length
                        #print()
                        if (int(sp) > int(dp)):
                            #print(num)
                            root2 = insert2(root2, [sp, dp, sip, dip, l,p])
                        else:
                            root2 = insert2(root2, [dp, sp, dip, sip, l,p])
      #cap.close()
      return root2
    except MemoryError:
        return root2

def cluster():          #centroids,online

    dd = {'a':[],'b':[], 'c':[], 'x': [], 'y': []}
    aap='none'
    for i in apps.items():

      coun = 0
        #print(coun)
      tupl = list(i)

      if ((tupl[0] == 'TCP') or (tupl[0]== 'SSL') or (tupl[0]=='URLENCODED-FORM') ):
        continue
      else:
        if tupl[1]:
            for j in range(0, len(tupl[1]), 5):        #to convert the 5 tuple into 5 dimensions of each coord of the dictionary
                # print(d)
                dd['a'].append(tupl[1][j])
                dd['b'].append(tupl[1][j+1])
                dd['c'].append(tupl[1][j+2])
                dd['x'].append(tupl[1][j+3])
                dd['y'].append(tupl[1][j+4])
                coun+=1
                aap=tupl[0]

        if coun:
            count["%s" %tupl[0]].append(coun)               #to save the no. of connections assoc with each app in the dictionary
        else:
            continue

      if online ==1:              #for online phase

        centr = np.array(centroids)

        x = dd['a']
        y = dd['b']
        z = dd['c']
        a = dd['x']
        b = dd['y']
        x=int(x[0]);y=int(y[0]);z=int(z[0]);a=int(a[0]);b=int(b[0])
        # print(x[0])
        don = []
        #print(len(centr))
        for i in range(len(centr)):
            don.append(math.sqrt(
                (pow((x - centr[i][0]), 2)) + pow((y - centr[i][1]), 2) + pow((z - centr[i][2]), 2) + pow(
                    (a - centr[i][3]), 2) + pow((b - centr[i][4]), 2)))
        ed = (math.sqrt(
                (pow((x - p[0]), 2)) + pow((y - p[1]), 2) + pow((z - p[2]), 2) + pow(
                    (a - p[3]), 2) + pow((b - p[4]), 2)))

        don = list(don)
        # mx=min(d,key=d.count)
        #mx = min(don)
        #print(mx)
        minpos=don.index(min(don))
        if ed < minpos:
            minpos = ed
            if int(minpos) < 10:
                print("flow is a peer-to-peer application")
            else:
                print("flow does not belong to any cluster or to the defined list of well-known port numbers, "
                      "it could be a potential new Client-Server application")
            var = 0
            return c_labels, var

        else:
            if int(min(don))<= 11:
                c_labels['%s' %minpos].append(aap)
                var=1
                return c_labels,var

                    #print("else")
                    #print(tupl[0],min(don))
         #           rang= list(range(49152,65535))
          #          p2 = ports.get("%s" % tupl[0], )  # testing
                    #print(int(p2[0]))

                #if (int(p2[0]) in well_known_p):  #or (int(p2[0]) in rang)):
                    #print("Application masqueraded in Well-Known port number")
                    #print("The traffic could possibly be P2P")
                      #print(ed)

           #         else:
                        #ran=list(range(0,1023))
                        #if int(p2[0] not in well_known_p):
                        #if (int(p2[0]) in ran):

                         #   print("It could be a potential new P2P application")

               # else:
                #    ran = list(range(0, 1023))
                    #print(ran)
                 #   if (int(p2[0]) in ran):             #port is not in well_known ports
                  #      print("flow does not belong to any cluster or to the list of well-known portt numbers, "
                   #           "it could be a potential new Client-Server application")


        #print(c_labels)

    if online==0:
        df = pd.DataFrame(dd)  # print(tupl[1][1])


        centr=np.array(centroids, np.float64)
        kmeans = KMeans(n_clusters= 12, init=centr, n_init=1, max_iter=1, algorithm='elkan')
        print(df)
        kmeans.fit(df)

        label= kmeans.labels_

        print(kmeans.labels_)
        print(kmeans.cluster_centers_)
        centroidss=np.array(kmeans.cluster_centers_)

        #plt.scatter(df['x'].values, df['y'].values, c=kmeans.labels_.astype(float), s=50, alpha=0.5)
        #plt.scatter(centroidss[:, 0], centroidss[:, 1],marker='s', color ='red', s=50)
        #plt.show()
        return label,centroidss

def getmax(lst):
    rt=[]
    v=lst[0]
    rt.append(v)
    for i in range(len(lst)):
        if v==lst[i]:
            continue
        else:
            if lst[i] not in rt:
                v=lst[i]
                rt.append(v)
    return rt
    #mx=max(lst,key=lst.count)
    #return mx


def clabels():
    v=0
    lst=[]
    for i in count.items():         #to label clusters with the diff applications
        if i[1]:
            lst=[]
            #print(i[1])
            x=int(i[1][0])
            #print(x,v)
            #print(label[v])     #v represents the index from where the flow entries start for each app in a given coord.
            #print(label[12])
            for j in range(v,v+int(x),1):
                lst.append(label[j])            #labels is the centroid assignments
            v+=int(x)
            if int(len(lst)) != 0:
                mx=getmax(lst)
                                #to count the max occuring centroid/label while clustering
                #print("max is",mx)
            if (int(len(mx))==1):
                c_labels['%s' %mx[0]].append(i[0])
            else:
                for j in range(len(mx)):
                    c_labels["%s" %mx[j]].append(i[0])

    print(c_labels)
    return c_labels

def flow_check():
    for i,j in zip(cc.items(),c_labels.items()):
        #print(i[0],j[0])
        t= i[1]         #apps corresp to training set
        u=j[1]          #corresp to new flow
        x=len(i[1])         #the no. of entries in the training centroid
        y=len(j[1])         #to find no. of entries in the online phase centroids
        #print(u)
        if x>=y:
            #print("x>y",x,y)
            for k in range(y):
                #print(u[k])
                if(u[k] in t):      #to find if there are any same applications under the same cluster and check their port equaloty
                    #print(u[k])
                    ap=u[k]
                    p1=port.get("%s" %ap, )    #training port numbers
                    p2=ports.get("%s" %ap, )    #testing
                    if p2[0] in p1:
                        print("flow belongs to cluster" , i[0] , "and application", ap) #"ports",p2[0], p1 )
                    else:
                        print("Masqueraded flow detected with", "\n application", ap,"and ports", p1,p2)
                        #cluster with bit torrent
                else:
                    print("application" ,u[k],"not found in the cluster")
        else:
            #print("x<y",x,y)
            if int(x)==0:
                print("applications",u, "assigned to cluster",j[0],"which is empty")
            for k in range(x):
                if(t[k] in u):
                    #print(t[k])
                    ap=t[k]
                    p1=port.get("%s" %ap, )
                    p2=ports.get("%s" %ap, )
                    if p2[0] in p1:
                        print("flow belongs to cluster \n", i[0], "and application \n", ap,) #"\n and ports "  )
                    else:
                        print("Masqueraded flow detected with ", "\n application", ap, "and ports" )

                else:
                    print("application ", u[k],"not found in cluster", x)



def clearup():

    apps = {'NNTP': [],'POP':[], 'FTP': [], 'SSH': [],'HTTP': [], 'BITTORRENT':[],'SMTP': [],'TELNET':[],'RTMP':[], 'SSL': [],'TCP': [],
            'DATA': [], 'nil': [], 'MYSQL': [], 'URLENCODED-FORM': []}  # to save the first 5 packets of the connections
    count = {'NNTP': [],'POP':[],'FTP': [], 'SSH': [],'HTTP': [],'BITTORRENT':[], 'SMTP': [],'TELNET':[],'RTMP':[], 'SSL': [], 'TCP': [],
             'DATA': [], 'nil': [], 'MYSQL': [], 'URLENCODED-FORM': []}  # to save the no. of connections in each
    c_labels = {'0': [], '1': [], '2': [],'3':[],'4':[],'5':[],'6':[],'7':[],'8':[],'9':[],'10':[],'11':[],'12':[]}
    ports = {'NNTP': [],'POP':[], 'FTP': [], 'SSH': [],'HTTP': [],'BITTORRENT':[], 'SMTP': [],'TELNET':[],'RTMP':[], 'SSL': [], 'TCP': [],
            'DATA': [], 'nil': [], 'MYSQL': [], 'URLENCODED-FORM': []}  # to save the port numbers of the applications

    return apps,count,c_labels,ports

if __name__ == '__main__':

    root=None
    online=int(0)
    label=[]

    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/smtpcap2.pcap'
    root = None
    root = fxn(root)
    print("done 2")

    filepath='C:/Users/Zaffar Iqbal Mir/Downloads/poptest.pcap'
    root=None
    root=fxn(root)

    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/ftp_train1.pcap'
    root = fxn(root)
    # print("done 1")
    filepath= 'C:/Users/Zaffar Iqbal Mir/Downloads/ftp.pcap'
    root=fxn(root)


    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/bit2.pcap'   # for http port 8088, http1.pcap'
    root = None
    root = fxn(root)
    # print("done 3")

    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/nntp.pcap'
    root = fxn(root)

    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/sshsql.pcap'
    root = None
    root = fxn(root)
    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/mysql_complete.pcap'
    root=fxn(root)

    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/pop32.pcap'
    root = None
    root = fxn(root)
    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/pop3.pcap'
    root = fxn(root)

    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/telnet-cooked.pcap'
    root = None
    root = fxn(root)
    print("done 5")

    print("Inorder traversal of the tree")
    inorder(root)
    #print("\n appa", apps)
    #print()
    centroids = [ [74,74,66,71,66],[74, 74, 66,90,66],[74,74,66,140,66],[74,74,66,230,66],[74,74,66,370,66],[74,74,66,500,66],
                  [78,74,66,850,60],[66,62,54,89,70],[66, 66, 54, 110,54],
                [66,66,54,300,60],[66,66,54,430,60],[66,62,54,1387,54]]

    root=None
    label,centroids=cluster()          #k means labels and updated centroids
    c_labels= clabels()                     #apps assigned to each cluster
    cc= c_labels
    port = ports

    apps = {'DATA-TEXT-LINES': [],'POP':[],'FTP': [], 'SSH': [],'HTTP': [],'BITTORRENT':[], 'SMTP': [],'TELNET':[],'RTMP':[], 'SSL': [],'TCP': [],
            'DATA': [], 'nil': [], 'MYSQL': [], 'URLENCODED-FORM': []}  # to save the first 5 packets of the connections
    count = {'DATA-TEXT-LINES': [],'POP':[],'FTP': [], 'SSH': [],'HTTP': [],'BITTORRENT':[], 'SMTP': [],'TELNET':[],'RTMP':[], 'SSL': [], 'TCP': [],
             'DATA': [], 'nil': [], 'MYSQL': [], 'URLENCODED-FORM': []}  # to save the no. of connections in each
    c_labels = {'0': [], '1': [], '2': [],'3':[],'4':[],'5':[],'6':[],'7':[],'8':[],'9':[],'10':[],'11':[],'12':[]}
    ports = {'DATA-TEXT-LINES': [],'POP':[], 'FTP': [], 'SSH': [],'HTTP': [],'BITTORRENT':[], 'SMTP': [],'TELNET':[],'RTMP':[], 'SSL': [], 'TCP': [],
            'DATA': [], 'nil': [], 'MYSQL': [], 'URLENCODED-FORM': []}  # to save the port numbers of the applications

    #filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/bit4.pcap'
    #root = fxn(root)


    #print("cc is", cc)
    #print(apps,count)
    online=int(1)
    root = None

    filepath= 'C:/Users/Zaffar Iqbal Mir/Downloads/poptest2.pcap'
    root =fxn(root)
    c_labels,var=cluster()      #centroids,int(1)
    #print("test1")
    if var == int(1):
        flow_check()
    apps, count, c_labels, ports = clearup()        #apps,count,c_labels,ports
    #print(apps)
    #print(ports)

    root = None
    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/bittrain.pcap'
    root = fxn(root)
    c_labels, var = cluster()
    # c_labels = cluster(centroids, int(1))
    # print("test5")
    if var == int(1):
        flow_check()
    apps, count, c_labels, ports = clearup()


    root = None
    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/ssh2.pcap' #sshtest.pcap
    root = fxn(root)
    c_labels,var = cluster()
    #print("test2")
    if var==int(1):
        flow_check()
    apps, count, c_labels, ports = clearup()

    root = None
    #filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/smtp.pcap'
    #root = fxn(root)
    #print(c_labels)
    #c_labels,var = cluster()
    #print("test3")
    #if var == int(1):
     #   flow_check()
    #apps, count, c_labels, ports = clearup()

    filepath='C:/Users/Zaffar Iqbal Mir/Downloads/sshtest.pcap'
    root=fxn(root)
    c_labels,var=cluster()
    #print("test3")
    if var == int(1):
        flow_check()
    apps, count, c_labels, ports = clearup()

    root = None
    filepath = 'C:/Users/Zaffar Iqbal Mir/Downloads/telnet-raw.pcap'
    root = fxn(root)
    c_labels,var = cluster()
    #print("teset4")
    if var == int(1):
        flow_check()
    apps, count, c_labels, ports = clearup()

