#!/usr/bin/env python3
# -*- coding=utf-8 -*-
import os
import time
import click
import linode_api4
import fabric
import requests
import requests.auth


class lets_encrypt:
    email = os.environ.get('LETS_ENCRYPT_EMAIL')

class linode:
    token = os.environ.get('LINODE_TOKEN')
    password = os.environ.get('LINODE_PASSWORD')
    client = linode_api4.LinodeClient(token)

    @classmethod
    def node(
        cls,
        label,
        ltype='g6-nanode-1',
        region='ap-south',
        image='linode/arch',
        recreate=False
    ):
        node = None
        # 查找已存在的实例
        node_list = cls.client.linode.instances(linode_api4.Instance.label==label)
        assert len(node_list) <= 1, '同一个label下不应该会出现多个实例'
        if len(node_list) == 1:
            pre_node = node_list[0]
            # 如果要求重建，则删除之前的节点，否则使用历史节点
            if recreate:
                pre_node.delete()
            else:
                node = pre_node
        # 如果没有实例，则建立实例
        if not node:
            node = cls.client.linode.instance_create(
                label=label,
                ltype=ltype,
                region=region,
                image=image,
                root_pass=cls.password,
                authorized_keys=[
                    '''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCnPZTSFaL9AbPrmECjdIdXGgr3v92+uI419MKc90O8qH/r7j+swhOnqE9BMWENA8F5n/zYfFYV/PgVn4pl1Y6QBAAzyUBLHwAc7KBmSbvB2xNahGTIn3/xyF8Lpj9mMubmIKxfojnM/g6cMPtWSS3b1OJ/YyRv/8J0yUAnGmn8WSS9eNJ5VMV+hK6Wc60zwZ7Sf+r5qJbuhLaXQl+dYhD7OubkV9h8uT9/3fSxFYwUuH2xyvjljojBj79XwXjBTP0+lfvJt6EXHR/vbQKeskh6nlmEWVwTnpYDk5/c48LHhtIyTINTx+KeT+qjnjySaNcAnSkZ6qorOsrDcu9vFNw5 erriy@msn.com'''
                ]
            )
        # 扩展函数
        def ready():
            while node.status!='running':
                print('系统[{}]等待中，3s后重试'.format(node.status))
                time.sleep(3)

        def run(cmds):
            # todo 链接失败重试，三次链接失败后再报错
            ready()
            c = fabric.Connection(host=node.ipv4[0], user='root', connect_kwargs={'password': cls.password})
            result = c.run(cmds)
            c.close()
            return result

        node.ready = ready
        node.run = run

        # 等待准备完成
        node.ready()

        return node


class name:
    name = os.environ.get('NAME_NAME')
    domain = os.environ.get('NAME_DOMAIN')
    token = os.environ.get('NAME_TOKEN')
    auth = requests.auth.HTTPBasicAuth(name, token)

    @classmethod
    def records(cls):
        with requests.get(
            'https://api.name.com/v4/domains/{}/records'.format(cls.domain),
            auth=cls.auth
        ) as r:
            return {
                x['host']:dict(
                    answer=x['answer'],
                    ttl=x['ttl'],
                    type=x['type'],
                    id=x['id'],
                )
                for x in r.json()['records']
            }

    @classmethod
    def create(cls, host, ip):
        record = dict(host=host, type='A', answer=ip, ttl=300)
        with requests.post(
            'https://api.name.com/v4/domains/{}/records'.format(cls.domain),
            auth=cls.auth
        ) as r:
            if r.status_code != 200:
                raise r.text

    @classmethod
    def update(cls, host, ip):
        records = cls.records()
        if host in records:
            req_method = requests.put
            url = 'https://api.name.com/v4/domains/{}/records/{}'.format(cls.domain, records[host]['id'])
        else:
            req_method = requests.post
            url = 'https://api.name.com/v4/domains/{}/records'.format(cls.domain)
        with req_method(url, auth=cls.auth, json=dict(host=host, type='A', answer=ip, ttl=300)) as r:
            print(r)


@click.group()
def cmds():
    pass


@cmds.command()
@click.option('--label', default='proxy', help='指定label，label为唯一显示名称')
@click.option('--ltype', default='g6-nanode-1')
@click.option('--region', default='ap-south', type=click.Choice([
    'ap-west', 'ca-central', 'ap-southeast', 'us-central', 'us-west', 'us-east', 'eu-west', 'ap-south', 'eu-central', 'ap-northeast'
]))
@click.option('--image', default='linode/arch')
@click.option('--subdomain', default='p', help='指定要使用的子域名')
@click.option('--recreate', is_flag=True, default=False, help='如果存在则强制重建')
@click.option('--reboot', is_flag=True, default=False)
def proxy_recreate(label, ltype, region, image, subdomain, recreate, reboot):
    # 打开实例
    print('打开{}实例'.format(label))
    node = linode.node(label, ltype, region, image, recreate)
    # 更新dns记录
    print('更新dns记录')
    name.update(subdomain, node.ipv4[0])
    # 环境安装
    print('开始初步安装环境并重启')
    node.run('''
        pacman -Syu --noconfirm htop git docker docker-compose tmux vim certbot &&
        systemctl enable docker &&
        echo "tcp_bbr" > /etc/modules-load.d/80-bbr.conf &&
        touch /etc/sysctl.d/80-bbr.conf &&
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.d/80-bbr.conf &&
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.d/80-bbr.conf &&
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.d/80-bbr.conf &&
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/80-bbr.conf
    ''')
    if reboot:
        node.reboot()
        time.sleep(15)
    # 服务启动
    print('启动docker')
    node.run('''
        rm -rf ~/dockers/ &&
        git clone https://github.com/Erriy/dockers.git &&
        cd dockers &&
        sed -i 's/NGINX_SERVER_NAME/{subdomain}.{domain}/g' v2ray/nginx.conf &&
        certbot certonly --standalone -d {subdomain}.{domain} --agree-tos -n -m {lets_encrypt_email} &&
        cp -L /etc/letsencrypt/live/{subdomain}.{domain}*/*.pem v2ray/ &&
        docker-compose up --force-recreate -d
    '''.format(
        subdomain=subdomain,
        domain=name.domain,
        lets_encrypt_email=lets_encrypt.email,
    ))


if __name__ == "__main__":
    cmds()

