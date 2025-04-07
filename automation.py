import json
import boto3
from datetime import datetime

def lambda_handler(event, context):
    #변경된 security group ID 추출
    invokingEvent = json.loads(event['invokingEvent'])
    resourceId = invokingEvent['configurationItem']['resourceId']

    #wsi-test Instance에 연결되어있는 Security Group 목록 추출
    ec2 = boto3.client('ec2')
    wsi_test = ec2.describe_instances(
        Filters=[{
            'Name': 'tag:Name',
            'Values': [
                'wsi-test'
            ]
        }]
    )
    wsi_test_security_groups = []
    for sg in wsi_test['Reservations'][0]['Instances'][0]['SecurityGroups']:
        wsi_test_security_groups.append(sg['GroupId'])

    #만약, resourId가 wsi-test Instance에 연결되어 있는 Security Group이 아니라면, 종료
    if resourceId not in wsi_test_security_groups:
        return

    #현재 설정되어 있는 Security Group 정보 확인
    security_group_info = ec2.describe_security_groups(GroupIds=[resourceId])
    
    #현재 설정되어 있는 값을 삭제
    current_ingress_rule = security_group_info['SecurityGroups'][0]['IpPermissions']
    current_egress_rule = security_group_info['SecurityGroups'][0]['IpPermissionsEgress']

    if current_ingress_rule:
      ec2.revoke_security_group_ingress(GroupId=resourceId, IpPermissions=current_ingress_rule)
    if current_egress_rule:
      ec2.revoke_security_group_egress(GroupId=resourceId, IpPermissions=current_egress_rule)

    # 기존 값 넣기
    ingress_permissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{
                'CidrIp': '104.28.226.210/32'
            }]
        },
        {
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'UserIdGroupPairs':[{
                    'GroupId': resourceId
                }]
        },
        {
            'IpProtocol': 'tcp',
            'FromPort': 3306,
            'ToPort': 3306,
            'UserIdGroupPairs':[{
                    'GroupId': resourceId
                }]
        }    
    ]
    egress_permissions=[
        {
            'IpProtocol': "-1",
            'FromPort': 0,
            'ToPort': 0,
            'IpRanges': [{
                'CidrIp': '172.31.0.0/16'
            }]
        }
    ]

    ec2.authorize_security_group_ingress(GroupId=resourceId, IpPermissions=ingress_permissions)
    ec2.authorize_security_group_egress(GroupId=resourceId, IpPermissions=egress_permissions)

    # 모든 설정을 변경했기에 COMPLIANT라고 출력하기
    config = boto3.client('config')
    response = config.put_evaluations
    config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invokingEvent['configurationItem']['resourceType'],
                'ComplianceResourceId': invokingEvent['configurationItem']['resourceId'],
                'ComplianceType': 'COMPLIANT',
                'Annotation': 'string',
                'OrderingTimestamp': invokingEvent['configurationItem']['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken']
    )
    return response
