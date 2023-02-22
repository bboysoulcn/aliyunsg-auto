# 监测公司的公网ip有没有变化
import requests
from requests.adapters import HTTPAdapter
import json
import time
import logging
import configparser
from aliyunsdkcore.client import AcsClient
from aliyunsdkecs.request.v20140526 import RevokeSecurityGroupRequest, AuthorizeSecurityGroupRequest, \
    DescribeSecurityGroupAttributeRequest

# 获取配置
get_ip_url = "http://realip.cc"
conf = configparser.ConfigParser()
conf.read('config.ini')
wechat_boot_url = conf.get('conf', 'wechat_boot_url')
access_key = conf.get('conf', 'access_key')
access_secret = conf.get('conf', 'access_secret')
area = conf.get('conf', 'area')
sgid = conf.get('conf', 'sgid')

# 初始化ecs对象
client = AcsClient(access_key, access_secret, area)

# 日志
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)
handler = logging.FileHandler("log.txt")
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)



def send_wechat(message):
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    body = {
        "msgtype": "markdown",
        "markdown": {
            "content": message,
        }
    }
    requests.post(wechat_boot_url, json.dumps(body), headers=headers)


class SgInstance:
    def get_sg_rule_ip(self, port_range, description, protocol, policy, priority):
        des_sg_rule_req = DescribeSecurityGroupAttributeRequest.DescribeSecurityGroupAttributeRequest()
        des_sg_rule_req.set_SecurityGroupId(sgid)
        try:
            response = client.do_action_with_exception(des_sg_rule_req)
            rule_content = json.loads(response)['Permissions']['Permission']
            for i in rule_content:
                if policy == i['Policy'] and int(priority) == i['Priority'] and protocol == i[
                    'IpProtocol'] and port_range == \
                        i['PortRange'] and description == i['Description']:
                    sourcecidrip = i['SourceCidrIp']
            return sourcecidrip
        except Exception as e:
            logger.error(e)

    def del_sg_rule(self, port_range, description, sourcecidrip, policy, priority, protocol):
        del_sg_rule_req = RevokeSecurityGroupRequest.RevokeSecurityGroupRequest()
        # 安全组id
        del_sg_rule_req.set_SecurityGroupId(sgid)
        # 策略accept or dennie
        del_sg_rule_req.set_Policy(policy)
        # 优先级
        del_sg_rule_req.set_Priority(priority)
        # 协议类型
        del_sg_rule_req.set_IpProtocol(protocol)
        # 端口范围
        del_sg_rule_req.set_PortRange(port_range)
        # 授权对象
        del_sg_rule_req.set_SourceCidrIp(sourcecidrip)
        # 描述
        del_sg_rule_req.set_Description(description)
        try:
            response = client.do_action_with_exception(del_sg_rule_req)
        except Exception as e:
            logger.error(e)

    def add_sg_rule(self, port_range, description, ip, policy, priority, protocol):
        add_sg_rule_req = AuthorizeSecurityGroupRequest.AuthorizeSecurityGroupRequest()
        # 安全组id
        add_sg_rule_req.set_SecurityGroupId(sgid)
        # 策略accept or dennie
        add_sg_rule_req.set_Policy(policy)
        # 优先级
        add_sg_rule_req.set_Priority(priority)
        # 协议类型
        add_sg_rule_req.set_IpProtocol(protocol)
        # 端口范围
        add_sg_rule_req.set_PortRange(port_range)
        # 授权对象
        add_sg_rule_req.set_SourceCidrIp(ip)
        # 描述
        add_sg_rule_req.set_Description(description)
        try:
            response = client.do_action_with_exception(add_sg_rule_req)
        except Exception as e:
            logger.error(e)


def change_ip(ip):
    sg = SgInstance()

    sections = conf.sections()
    for i in sections:
        if i != 'conf':
            policy = conf.get(i, 'policy')
            priority = conf.get(i, 'priority')
            protocol = conf.get(i, 'protocol')
            port_range = conf.get(i, 'port_range')
            description = conf.get(i, 'description')
            sourcecidrip = sg.get_sg_rule_ip(port_range, description, protocol, policy, priority)
            # 删除规则
            sg.del_sg_rule(port_range, description, sourcecidrip, policy, priority, protocol)
            # 创建规则
            sg.add_sg_rule(port_range, description, ip, policy, priority, protocol)
    # 获取修改之后的公网ip
    time.sleep(10)
    sourcecidrip = sg.get_sg_rule_ip(port_range, description, protocol, policy, priority)
    return sourcecidrip


if __name__ == '__main__':
    # ip1当前公网ip ip2之前的ip
    ip2 = '1.1.1.1'
    while True:
        # 获取当前公网ip
        try:
            s = requests.Session()
            s.mount('http://', HTTPAdapter(max_retries=3))
            res = s.get(get_ip_url,timeout=5)
            ip1 = json.loads(res.text)["ip"]
        except Exception as e:
            logger.error(e)
            continue
        if ip1 != ip2 and ip2 != None:
            sourcecidrip = change_ip(ip1)
            ip2 = ip1
            logger.info('ip修改成功')
            send_wechat("### 公司公网ip已经修改\n\n- 当前公司的公网ip变为: " + ip1 + "\n- 当前安全组上的公网ip为: " + sourcecidrip)
        else:
            print('ip不变')
            time.sleep(10)
