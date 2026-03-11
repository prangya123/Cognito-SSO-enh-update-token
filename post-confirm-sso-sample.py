import json
import logging
import boto3


from datetime import timezone


logger = logging.getLogger(__name__)
logger.setLevel('INFO')

client = boto3.client('cognito-idp', region_name='us-west-2')
snsClient = boto3.client('sns', region_name='us-west-2')

def lambda_handler(event, context):
    print("Post Confirm-Authentication started")
    print("event is :", event)
    print("context is:", context)
    print("---------------------------------")
    print(event['userName'])
    print("User pool =", event['userPoolId'])
    print("User ID =", event['userName'])
    user_pool_id = event['userPoolId']
    username = event['userName']
    
    print("*****************************************")
    
    response1 = get_user_attributes(user_pool_id, username)
    print("response1 is:",response1)
    
    ###Find User Created Date
    # Assuming response1['UserCreateDate'] is a datetime object
    user_create_date = response1['UserCreateDate']
    
    # Convert to UTC
    utc_date = user_create_date.astimezone(timezone.utc)
    
    # Format the UTC date UserCreateDate_fmtd in formated UTC version
    UserCreateDate_fmtd = utc_date.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    print(UserCreateDate_fmtd)


    print("*****************************************")
    O365group, O365group_list_new = process_user_attributes(response1)
    print(f"O365group: {O365group}")
    print(f"O365group_list_new: {O365group_list_new}")
 
    
    response2 = get_existing_user_groups(user_pool_id, username)
    print("response2 is:",response2)
    
    Existing_User_Gr_list = [group['GroupName'] for group in response2.get('Groups', [])]
    print("Existing_User_Gr_list is:",Existing_User_Gr_list)
    
    
    response3 = list_all_groups(user_pool_id)
    print("response3 is:",response3)
    
    CognitoGroup_list = [group['GroupName'] for group in response3.get('Groups', [])]
    print("CognitoGroup_list is:",CognitoGroup_list)
    
    
    response = update_user_to_group(O365group_list_new, Existing_User_Gr_list, CognitoGroup_list, user_pool_id, username)
    
    print("*****************************************")
    print("END OF POST AUTH")
    print(response)
    return event

def get_user_attributes(user_pool_id, username):
    response = client.admin_get_user(
        UserPoolId=user_pool_id,
        Username=username
    )
    return response

def process_user_attributes(response):
    O365group = []
    O365group_list_new = []
    for attribute in response['UserAttributes']:
        print("---------attribute--------------")
        print(attribute)
        if attribute['Name'] == 'custom:group':
            group_values = attribute['Value'].strip('[]').split(', ')
            O365group.extend(group_values)
            O365group_list_new.extend(
                [group.replace('MXSSO-', '') if group.startswith('MXSSO-') else group for group in group_values])
            print(f"custom:group Value: {attribute['Value']}")
            
    print("*****************************************")
    return O365group, O365group_list_new

def get_existing_user_groups(user_pool_id, username):
    response = client.admin_list_groups_for_user(
        UserPoolId=user_pool_id,
        Username=username
    )
    #print(f"Existing_User_Gr_list: {response.get('Groups', [])}")
    #print("*****************************************")
    return response

def list_all_groups(user_pool_id):
    response = client.list_groups(
        UserPoolId=user_pool_id
    )
    #print(f"Group Names: {response.get('Groups', [])}")
    #print("*****************************************")
    return response

def admin_add_user_to_group(user_pool_id, username, group):
    response = client.admin_add_user_to_group(
        UserPoolId=user_pool_id,
        Username=username,
        GroupName=group
    )
    print(f"User {username} added to group {group} in User Pool {user_pool_id}")
    return response

def update_user_to_group(O365group_list_new, Existing_User_Gr_list, CognitoGroup_list, user_pool_id, username):
    Add_to_cognito_group_list = []
    Remove_from_cognito_group_list = []
    Flag_group_list = []
    message = {}
    response = {}  # Define the response variable

    if all(group not in CognitoGroup_list for group in O365group_list_new):
        Flag_group_list.extend(O365group_list_new)
        print("*********************************************")
        print("USER HAS NO MATCH COGNITO GROUP,TRIGGER EMAIL TO SUPPORT")
        print(f"Flag_group_list: {Flag_group_list}")
        #
        # message = {
        #     "User Pool": "us-west-2_COwUvf88U",
        #     "User Name": username,
        #     "Error": "USER HAS NO MATCH ASSIGN COGNITO GROUP",
        #     "Flag_group_list": Flag_group_list
        # }
        message = {
            "User Pool": "us-west-2_09zqIUrb6",
            "User Name": username,
            "Error": "USER HAS NO ASSIGNED COGNITO GROUP",
            "Flag_group_list": Flag_group_list
        }
        messageJSON = json.dumps(message, indent=2)
        response7 = snsClient.publish(
            TopicArn='arn:aws:sns:us-west-2:207826251819:send-to-prangyakar',
            Subject='----USER HAS NO MATCH ASSIGN COGNITO GROUP---',
            Message=messageJSON
        )
        print(f"response7 is {response7}")
        print("Message published:send-to-prangyakar-STAGE")

    for group in O365group_list_new:
        if group not in Existing_User_Gr_list:
            Add_to_cognito_group_list.append(group)

    for group in Existing_User_Gr_list:
        if group not in O365group_list_new:
            Remove_from_cognito_group_list.append(group)

    print(f"Add_to_cognito_group_list: {Add_to_cognito_group_list}")
    print(f"Remove_from_cognito_group_list: {Remove_from_cognito_group_list}")

    if not Add_to_cognito_group_list and not Remove_from_cognito_group_list:
        print("Existing_User_Gr_list is same as groups listed in O365group_list")
        print("User role or group is same as o365 role or group")
    else:
        for group in Add_to_cognito_group_list:
            if group in CognitoGroup_list:
                print(f"New group: {group} listed in Add_to_cognito_group_list is already exists in CognitoGroup_list")
                print(f"Add user: {username} to group:{group}")
                response4 = admin_add_user_to_group(user_pool_id, username, group)
                print("response4 is", response4)
            else:
                print(f"New group: {group} listed in Add_to_cognito_group_list DOES NOT EXISTS in CognitoGroup_list")
                Flag_group_list.append(group)

        for group in Remove_from_cognito_group_list:
            if group in CognitoGroup_list:
                print(f"New group: {group} listed in Remove_from_cognito_group_list is already exists in CognitoGroup_list")
                print(f"Remove user: {username} from group:{group}")
                response6 = client.admin_remove_user_from_group(
                    UserPoolId=user_pool_id,
                    Username=username,
                    GroupName=group
                )
                print(f"User {username} removed from group {group} in User Pool {user_pool_id}")
                print(f"response6 is {response6}")

    if len(Flag_group_list) == 0:
        print("The list is empty")
        print("No Flagged Groups")
    else:
        print(f"Flag_group_list: {Flag_group_list}")
        print("*********************************************")
        print("NEW ENTRAID GROUP FOUND, TRIGGER EMAIL TO SUPPORT")
        print(f"Send email to SUPPORT as below listed groups are assigned in ENTRAID but not in Cognito")
        #
        # message = {
        #     "User Pool": "us-west-2_HtblPYLar",
        #     "User Name": username,
        #     "Error": "USER BELONGS TO FOLLOWING GROUPS WHICH IS NOT LISTED IN COGNITO",
        #     "Flag_group_list": Flag_group_list
        # }
        
        message = {
            "User Pool": "us-west-2_09zqIUrb6",
            "User Name": username,
            "Error": "USER BELONGS TO FOLLOWING GROUPS WHICH IS NOT LISTED IN COGNITO",
            "Flag_group_list": Flag_group_list
        }
        messageJSON = json.dumps(message, indent=2)
        response8 = snsClient.publish(
            TopicArn='arn:aws:sns:us-west-2:207826251819:send-to-prangyakar',
            Subject='----USER HAS NO MATCH ASSIGN COGNITO GROUP---',
            Message=messageJSON
        )
        print(f"response8 is {response8}")
        print("Message published:send-to-prangyakar,env:STAGE")

    return json.dumps(message)  # Return the message instead of response
    
