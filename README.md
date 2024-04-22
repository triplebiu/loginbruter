# loginbruter

针对各个目标，需要自行提取js，并处理好输入输出。

逻辑部分也需要根据具体目标自己写。


## 使用
```bash
> python3 loginbruter.py -h 
usage: loginbruter.py [-h] (-u USERNAME | -U USERLIST) (-p PASSWORD | -P PWDLIST) [-m {C,P}] [-t THREAD]

optional arguments:
  -h, --help   show this help message and exit
  -u USERNAME  username split with , eg: root,admin
  -U USERLIST  username list file eg: ./username.txt
  -p PASSWORD  passwords split with , eg: admin,root,123456
  -P PWDLIST   passwords list file, eg: ./password.txt
  -m {C,P}     brute mode, C(luster bomb) or P(itchfork), default=C
  -t THREAD    mutli threads, default 3 threads

> python3 loginbruter.py -U username.txt -P pass.txt -m C -t 50
```

## todo

加入图形验证码识别。