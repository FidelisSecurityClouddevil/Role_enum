import boto3
from prettytable import PrettyTable
import fnmatch
import argparse
import sys


class Role:

   def __init__(self, name, arn ='',path='', Assume_role= False,inline_policy= [], managed_policy= [], s3_permissions = False, EC2_permissions =False, EKS_permissions =False, Assume_role_policy_document = False):
      self.arn = arn
      self.name = name
      self.path = path
      self.Assume_role  = Assume_role
      self.inline_policy = inline_policy
      self.managed_policy = managed_policy
      self.s3_permissions = s3_permissions
      self.EC2_permissions = EC2_permissions
      self.EKS_permissions = EKS_permissions
      self.Assume_role_policy_document = Assume_role_policy_document

def get_object_by_name(lst_of_objects, role_name):
    for obj in lst_of_objects:
       if role_name == obj.name:
          return obj

    return



def search_pattern_in_lst(lst, pattern):
   matching = fnmatch.filter(lst, pattern)
   if matching:
      return True
   return False


def is_role_in_user_policy(policy_lst, role_arn, client, username):
   for policy_arn in policy_lst:
      policy = client.get_policy(PolicyArn=policy_arn)
      policy_version = client.get_policy_version(PolicyArn=policy_arn,VersionId=policy['Policy']['DefaultVersionId'])
      for i in range(len(policy_version['PolicyVersion']['Document']['Statement'])):
         Effect = (policy_version['PolicyVersion']['Document']['Statement'][i]['Effect'])
         Resource = (policy_version['PolicyVersion']['Document']['Statement'][i]['Resource'])
         Action = (policy_version['PolicyVersion']['Document']['Statement'][i]['Action'])
         if Effect == 'Allow' and  'sts:AssumeRole' in Action and role_arn in Resource:
            return True
      
   return False


def get_attached_policies_from_group(client, policy_user_lst):
   groups = client.list_groups()['Groups']
   for dict in groups:
      group_policies = (client.list_attached_group_policies(GroupName=dict['GroupName'])['AttachedPolicies'])
      for policy in  group_policies:
         policy_user_lst.append(policy['PolicyArn'])

def get_attached_policies_from_user(client, policy_user_lst, username):
   attached_user_policies = client.list_attached_user_policies(UserName=username)['AttachedPolicies']
   for policy in attached_user_policies:
      policy_user_lst.append(policy['PolicyArn'])


def get_assume_role_lst (role_object_list, Role_list, policy_usr_lst, user_arn, account_id):

   for key in Role_list:
       role_name =  key['RoleName']
       role_arn = key['Arn']
       role_obj = get_object_by_name(role_object_list, role_name)
       assume_role_policy_doc = key['AssumeRolePolicyDocument']
       for i in range (len(assume_role_policy_doc['Statement'])):
          Effect = assume_role_policy_doc['Statement'][i]['Effect']
          who_can_asusme_role = assume_role_policy_doc['Statement'][i]['Principal']
          if 'AWS' in who_can_asusme_role and Effect == 'Allow':
            principal = who_can_asusme_role['AWS']
            if principal == '*' or principal == user_arn:
               role_obj.Assume_role = True
            elif principal == account_id or principal == 'arn:aws:iam::' + account_id + ':root':
               if is_role_in_user_policy(policy_user_lst,role_arn,client,username):
                  assume_role_user_lst.append(role_ar)
                  role_obj.Assume_role = True


def attach_role_policy(client, role_object_list, role_list):
   for key in role_list:
       role_name =  key['RoleName']
       role_obj = get_object_by_name(role_object_list, role_name)
       role_arn = key['Arn']
       get_policy_for_role(role_name,role_obj, client)
 


def build_role_object_lst(role_list, role_object_list):
   for key in role_list:
       role_name =  key['RoleName']
       role_arn = key['Arn']
       role_path = key['Path']
       role_object_list.append(Role(role_name, role_arn, role_path))


def get_assume_role_policy_doc(iam, role_obj):
   role = iam.Role(role_obj.name)
   role_obj.Assume_role_policy_document = role.assume_role_policy_document


def print_output(role_obj_lst, flag, role_obj):

   if flag == 'enum_roles':
      table = PrettyTable(['Role_name','Role_arn', 'Assume_role', 'S3_permissions', 'EC2_permissions','EKS_permissions' ])
      for role_obj in role_obj_lst:
         table.add_row([role_obj.name, role_obj.arn, role_obj.Assume_role, role_obj.s3_permissions, role_obj.EC2_permissions, role_obj.EKS_permissions])
      print(table)

   elif flag == 'describe':
      print()
      print('Role Name: ' + str(role_obj.name)+ '\n')
      print('Assume_role_policy_document: \n')
      print(str(role_obj.Assume_role_policy_document)+ '\n')
      print('Inline_role_policy_documents:\n ')
      for inline_doc in role_obj.inline_policy:
         print(str(inline_doc)+'\n')
      print('Managed_role_policy_documents:\n ')
      for managed_doc in role_obj.managed_policy:
         print(str(managed_doc)+'\n')

def get_policy_for_role(role_name, role_obj, client):
    
    role_name_policy_dict_inline = client.list_role_policies(RoleName=role_name)
    role_name_policy_dict_managed = client.list_attached_role_policies(RoleName = role_name)
    managed_policy_names = role_name_policy_dict_managed['AttachedPolicies']
    for i in range (len(managed_policy_names)):
       policy_name = managed_policy_names[i]['PolicyName']
       policy_arn =  managed_policy_names[i]['PolicyArn']
       policy = client.get_policy(PolicyArn=policy_arn)
       policy_version = client.get_policy_version(PolicyArn=policy_arn,VersionId=policy['Policy']['DefaultVersionId'])
       Document = policy_version['PolicyVersion']['Document']
       role_obj.managed_policy.append(Document)
       for j in range(len(policy_version['PolicyVersion']['Document']['Statement'])):
          Effect = (policy_version['PolicyVersion']['Document']['Statement'][j]['Effect'])
          Action = (policy_version['PolicyVersion']['Document']['Statement'][j]['Action'])
          if Effect == 'Allow':
           
             role_obj.s3_permissions  = search_pattern_in_lst(Action, '*s3*') or role_obj.s3_permissions 
             role_obj.EC2_permissions = search_pattern_in_lst(Action, '*ec2*') or role_obj.EC2_permissions
             role_obj.EKS_permissions = search_pattern_in_lst(Action, '*eks*') or role_obj.EKS_permissions


    for policy in role_name_policy_dict_inline['PolicyNames']:
       policy_dict = client.get_role_policy(RoleName=role_name, PolicyName=policy)
       inline_document = policy_dict['PolicyDocument']
       role_obj.inline_policy.append(inline_document)
       for j in range(len(inline_document['Statement'])):
          Effect = (inline_document['Statement'][j]['Effect'])
          Action = (inline_document['Statement'][j]['Action'])
          if Effect == 'Allow':
             role_obj.s3_permissions  = search_pattern_in_lst(Action, '*s3*') or role_obj.s3_permissions
             role_obj.EC2_permissions = search_pattern_in_lst(Action, '*ec2*') or role_obj.EC2_permissions
             role_obj.EKS_permissions = search_pattern_in_lst(Action, '*eks*') or role_obj.EKS_permissions
 
def validate_arguments(args, parser):


   if args.help:
      parser.print_usage()
      sys.exit()

   if args.aws_access_key == False or  args.aws_secret == False:
      print('please provide both access key and access key secret')
      sys.exit()

   if args.enum_roles == True :
         
      if args.describe != False:
          print('It is illegal to choose both enum_roles flag with describe flag')
          sys.exit()
      elif args.assume_role != False:
          print('It is illegal to choose both enum_roles flag with assume_role flag')
          sys.exit()
   
   elif args.describe !=False:
      if args.assume_role != False:   
         print('It is illegal to choose both describe flag with assume role flag')
         sys.exit()
    




def describe_role(role_name, client, iam):
   try:
      role_data = client.get_role(RoleName=role_name)
      new_role = Role(role_name, role_data['Role']['Arn'] ,'', '', [],[],'','', role_data['Role']['AssumeRolePolicyDocument'] )
      get_policy_for_role(role_name, new_role, client)
      get_assume_role_policy_doc(iam, new_role)
      print_output('', 'describe' ,new_role)
   except Exception as e:
      print('Failed to describe role')
      print(e)


def assume_role(role_arn, client, args):
   
   try:
      sts_client = boto3.client('sts', aws_access_key_id = args.aws_access_key, aws_secret_access_key=args.aws_secret)
      response = sts_client.assume_role(RoleArn = role_arn ,RoleSessionName="AssumeRoleSession1")
      credentials = (response['Credentials'])
      assumed_role_session = boto3.Session(aws_access_key_id=credentials["AccessKeyId"],aws_secret_access_key=credentials["SecretAccessKey"],aws_session_token=credentials["SessionToken"])
    
      access_key = (credentials["AccessKeyId"])
      secret_key = (credentials["SecretAccessKey"])
      session_token = (credentials["SessionToken"])
      print('successfully assumed the role '+ (role_arn.split('/')[-1]) + '\n')
      print('access_key: ' + str(access_key) +'\n')
      print('secret_key: ' + str(secret_key+ '\n'))
      print('session_token: '+ str(session_token) + '\n')
   except Exception as e:
      print('Failed to assume role')
      print(e)


def msg(name=None):
    return '''
         -aws_access_key:                       AWS access key.
         -aws_secret:                           AWS secret access key.
         -enum_roles:                           Enumerate  IAM roles.
         -describe <role_name>:                 Describing details on provided role.
         -assume_role <role_arn>:               Assuming the role provided.
         -help:                                 help.
            '''



def  main():

   parser = argparse.ArgumentParser(description='IAM roles enumerator ', usage=msg())
   parser.add_argument('-aws_access_key',default= False )
   parser.add_argument('-aws_secret' ,default= False )
   parser.add_argument('-enum_roles',action='store_true',default= False )
   parser.add_argument('-describe',default= False )
   parser.add_argument('-assume_role' ,default= False )
   parser.add_argument('-help', action = 'store_true')

   args = parser.parse_args()
   validate_arguments(args, parser)

   try: 
      assume_role_user_lst = []
      group_user_lst = []
      policy_user_lst = []
      role_object_list = []
      client = boto3.client('iam',aws_access_key_id = args.aws_access_key, aws_secret_access_key=args.aws_secret)

      if args.assume_role != False:
         assume_role(args.assume_role, client, args)  
   
      elif args.describe != False:
         iam = boto3.resource('iam',aws_access_key_id = args.aws_access_key, aws_secret_access_key=args.aws_secret)
         describe_role(args.describe, client, iam)

      elif args.enum_roles:
         user_arn = boto3.client('sts',aws_access_key_id = args.aws_access_key, aws_secret_access_key=args.aws_secret).get_caller_identity()['Arn']
         username = client.get_user()["User"]["UserName"]
         account_id = boto3.client('sts',aws_access_key_id = args.aws_access_key, aws_secret_access_key=args.aws_secret).get_caller_identity().get('Account')
         Role_list = client.list_roles()['Roles']
         build_role_object_lst(Role_list, role_object_list)  
         get_attached_policies_from_user(client, policy_user_lst, username)
         get_attached_policies_from_group(client, policy_user_lst)       
         get_assume_role_lst(role_object_list,Role_list, policy_user_lst, user_arn, account_id)
         attach_role_policy(client, role_object_list, Role_list)     
         print_output(role_object_list, 'enum_roles' ,'')
   
   except Exception as e:
      print(e)



if __name__ == '__main__':
   main()
