#!/bin/bash
# author: HPCM
# time: 2022/12/30 23:11
# file: 01-禁用异常IP登录.sh
source /etc/profile

# ##################### param ##############################
# 允许IP登录失败次数, 超过将禁用IP
fail_count=2

# ##################### function ##############################
# 初始化黑名单
# usage:
#	    init_blacklist
function init_blacklist {
  ipset list blacklist 1>/dev/null
  if [ ! $? -eq 0 ]; then
    ipset create whitelist hash:ip timeout 259200 hashsize 4096 maxelem 1000000
    ipset list blacklist >/dev/null 1>&2
    if [ ! $? -eq 0 ]; then
      echo "init ipset blacklist fail!"
      exit 1
    fi
  fi
}

# ##################### function ##############################
# 检索异常IP
# usage:
#	    check_address
function check_address {
  #lastb | grep "-" | awk '{arr[$3]++} END{for(i in arr) if(arr[i]>'${fail_count}'){print i "\t=>\t" arr[i]}}'
  raw_fails=$(lastb | grep "-" | awk '{arr[$3]++} END{for(i in arr) if(arr[i]>'$fail_count'){print i}}')
  fails=$(ipset list blacklist)
  add_count=0

  echo "##################### $(date +'%Y-%m-%d %H:%M:%S') ###########################"
  for addr in $raw_fails; do
    if ! echo $fails | grep "$addr" 1>/dev/null 2>&1; then
      ipset add blacklist $addr
      if [ ! $? -eq 0 ]; then
        echo "ipset add address $addr failed!"
        exit 1
      else
        echo "address $addr added!"
      fi
      ((add_count++))
    fi
  done
  echo "blacklist add count $add_count success!"
}

init_blacklist
check_address

