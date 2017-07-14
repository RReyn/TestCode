# CheckInterface.sh

## 使用方法

```
Usage: ./CheckInterface.sh <IFNAME>
Argument:
<IFNAME>   Interface name

Return:
	"CKIF:Non-exist"  -- 接口不存在, 返回值为1 
	"CKIF:InvalidArg" -- 参数错误，返回值为2
	网卡类型,如"CKIF:Intel"、"CKIF:Broadcom" -- 网卡存在时打印网卡品牌，返回值为0 

```

