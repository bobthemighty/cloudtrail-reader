from collections import Counter, defaultdict
import gzip
import json
import boto3

import os
import pprint

import slackweb
from pydblite import Base

events = Counter()
record_count = 0
file_count = 0

pp = pprint.PrettyPrinter(indent=4)


class Inventory:

    def __init__(self, access_key, access_secret):
        self.client = boto3.resource("ec2")
        self.create_database()

    def create_database(self):
        self.db = Base("test.pdl")
        if not self.db.exists():
            self.db.create("resource", "name", "env")
        self.db.open()

    def fetch_instance(self, id):
        try:
            instances = self.client.instances.filter(InstanceIds=[id])
            for instance in instances:
                tags = {t["Key"]: t["Value"] for t in instance.tags}
                env = tags["Env"] if "Env" in tags else tags["Environment"]
                self.db.insert(resource=id, name=tags["Name"], env=env)
        except Exception as e:
            print(e)
            self.db.insert(resource=id, name=id, env="")

    def get_instance(self, id):
        instance = self.db(resource=id)
        if not instance:
            self.fetch_instance(id)
            instance = self.db(resource=id)

        return instance[0] if instance else None

    def fetch_network_interface(self, id):
        c = self.client.meta.client
        try:
            data = c.describe_network_interfaces(NetworkInterfaceIds=[id])
            nif = data["NetworkInterfaces"][0]
            if "Attachment" in nif:
                instance = self.get_instance(nif["Attachment"]["InstanceId"])
                if instance:
                    self.db.insert(resource=id,
                                   name=instance["name"],
                                   env=instance["env"])
        except Exception as e:
            print(e)
            self.db.insert(resource=id,
                           name=id,
                           env="")

    def add_group(self, id, name):
        self.db.insert(resource=id, name=name, env="")

    def get_network_interface(self, id):
        nif = self.db(resource=id)
        if not nif:
            self.fetch_network_interface(id)
            nif = self.db(resource=id)
        return nif[0] if nif else None

    def fetch_security_group(self, id):
        c = self.client.meta.client
        try:
            groups = c.describe_security_groups(GroupIds=[id])
            for group in groups["SecurityGroups"]:
                self.db.insert(resource=id, name=group["GroupName"])
        except Exception as e:
            print(e)

    def get_security_group(self, id):
        group = self.db(resource=id)
        if not group:
            self.fetch_security_group(id)
            group = self.db(resource=id)
        return group[0] if group else None

    def get_resource_name(self, id):
        resource = self.db(resource=id)
        return resource[0]["name"] if resource else None

inv = Inventory(
    "AKIAIOHYTIMXG67YIWSQ",
    "MxcVT1X62LS2uoWlj3Jdo2a0uDBxLzmxxIVfnR6i")


def skip(msg):
    pass


def format_list(l):
    return map(lambda s: "* "+s, l).join("\n")


def format_tags(l):
    return "\n".join(map(lambda e: "* "+e["key"] + ":" + e["value"] + "\n", l))


def user_and_ip(msg):
    if "userName" in msg["userIdentity"]:
        user = msg["userIdentity"]["userName"]
        sourceip = msg["sourceIPAddress"]
    else:
        user = msg["userIdentity"]["arn"]
        user = user.split("/")
        user = user[-1]
        sourceip = msg["sourceIPAddress"]

    return user, sourceip


def format_policy(doc):
    return pp.pformat(doc)

class MessageFormatter:

    def __init__(self, msg):
        self.msg = msg
        self.build_user_and_ip()
        self.request = self.msg["requestParameters"] or defaultdict(str)
        self.response = self.msg["responseElements"]
        self.build()

    def build_user_and_ip(self):
        if "userName" in self.msg["userIdentity"]:
            user = self.msg["userIdentity"]["userName"]
            sourceip = self.msg["sourceIPAddress"]
        else:
            user = self.msg["userIdentity"]["arn"]
            user = user.split("/")
            user = user[-1]
            sourceip = self.msg["sourceIPAddress"]

        self.user = "{}@{}".format(user, sourceip)

    def success_title(self):
        return self.msg["eventName"]

    def failure_title(self):
        return self.msg["eventName"] + " failed"

    def success_text(self):
        pass

    def failure_text(self):
        pass

    def color(self):
        pass

    def fields(self):
        pass

    @property
    def default_failure_fields(self):
        return {
            "error": self.msg["errorMessage"],
            "user": self.user
            }

    def failure_fields(self):
        return [self.default_failure_fields]

    def build(self):
        pass

    def format(self):
        is_error = "errorMessage" in self.msg
        fields_source = self.failure_fields(
            ) if is_error else self.fields() or {}
        fields = []
        for fieldset in fields_source:
            for k, v in fieldset.items():
                fields.append({
                    "title": k,
                    "value": v
                })
        attachment = {
            "title": self.failure_title() if is_error else self.success_title(),
            "text": self.failure_text() if is_error else self.success_text(),
            "color": self.color() or ("warning" if is_error else None),
            "fields": fields
        }

        return {k: v for k, v in attachment.items() if v is not None}


def instance_name(id):
    instance = inv.get_instance(id)
    if instance:
        return "{} ({})".format(instance["name"], instance["env"])
    return id


def resource_name(id):
    name = inv.get_resource_name(id)
    return name or id


def group_name(id):
    group = inv.get_security_group(id)
    return group["name"] if group else id


class TerminateInstancesFormatter(MessageFormatter):

    def build(self):
        self.instances = []
        if self.msg["responseElements"] is None:
            for instance in self.request["instancesSet"]["items"]:
                self.instances.append(instance["instanceId"])
            return

        for instance in self.response["instancesSet"]["items"]:
            self.instances.append("* {} (was {})".format(
                instance_name(instance["instanceId"]),
                instance["previousState"]["name"]))

    def success_title(self):
        return "{} instances were terminated".format(len(self.instances))

    def failure_title(self):
        return "Failed to terminate {0} instances".format(len(self.instances))

    def success_text(self):
        return "User {} terminated the following instances:\n{}".format(
            self.user, "\n".join(self.instances)
        )

    def failure_text(self):
        return "failed to terminate the following instances:\n".format(
            "\n".join(self.instances))

    def color(self):
        return "danger"


class RestoreDBInstanceFromDBSnapshotFormatter(MessageFormatter):

    def build(self):
        self.instance = self.msg["requestParameters"]["dBInstanceIdentifier"]
        self.snapshot = self.msg["requestParameters"]["dBSnapshotIdentifier"]

    def success_title(self):
        return "DB Instance Restored"

    def failure_title(self):
        return "Failed restoring DB instance"

    def success_text(self):
        return "Instance *{}* restored from snapshot {}\n\
                User: {}".format(self.instance, self.snapshot,
                                 self.user)

    def failure_fields(self):
        return[self.default_failure_fields, {
            "instance": self.instance,
            "snapshot": self.snapshot
        }]


class CreateTagsFormatter(MessageFormatter):

    def build(self):
        self.resources = [
            "* " +
            resource_name(r["resourceId"])
            for r in self.msg["requestParameters"]["resourcesSet"]["items"]]
        self.tags = {t["key"]: (t["value"] if "value" in t else "")
                     for t in self.msg["requestParameters"]["tagSet"]["items"]}

    def success_title(self):
        return "{} Instances tagged".format(len(self.resources))

    def failure_title(self):
        return "Failed to tag {} instances".format(len(self.resources))

    def fields(self):
        return [self.tags]

    def success_text(self):
        return "User {} tagged the following resources:\n{}".format(
            self.user, self.resources)

    def failure_text(self):
        return "User {} attempted to tag the following resources:\n{}".format(
            self.user, self.resources)

    def failure_fields(self):
        return[
            self.default_failure_fields,
            self.tags
        ]


class ModifyDBInstanceFormatter(MessageFormatter):

    def build(self):
        self.instance = self.msg["requestParameters"]["dBInstanceIdentifier"]

    def success_title(self):
        return "Database instance modified"

    def failure_title(self):
        return "Failed to modify database instance"

    def fields(self):
        return [{
                "user": self.user,
                "instance": self.instance,
                },
                self.msg["requestParameters"]
                ]

    def failure_fields(self):
        return [self.default_failure_fields, self.msg["requestParameters"]]


class CreateDBInstanceFormatter(MessageFormatter):

    def build(self):
        self.instance = self.request["dBInstanceIdentifier"]

    def success_title(self):
        return "Database instance created"

    def failure_title(self):
        return "Failed to create database instance"

    def fields(self):
        return [{
                "user": self.user,
                "instance": self.instance,
                },
                self.msg["requestParameters"]
                ]

    def failure_fields(self):
        return [self.default_failure_fields, self.msg["requestParameters"]]


class RunInstancesFormatter(MessageFormatter):

    def build(self):
        self.instances = []
        if self.msg["responseElements"] is None:
            self.instances = [
                "* {} x {}".format
                (item["imageId"], item["minCount"])
                for item in self.request["instancesSet"]["items"]]
        else:
            self.instances = [
                "* {} ({})".format(
                    instance_name(item["instanceId"]),
                    item["networkInterfaceSet"]["items"][0]["privateIpAddress"])
                for item in self.response["instancesSet"]["items"]]

    def get_location(self):
        if "availabilityZone" in self.msg["requestParameters"]:
            return "availabilityZone", self.msg[
                "requestParameters"]["availabilityZone"]
        elif "subnetId" in self.msg["requestParameters"]:
            return "subnet", self.msg["requestParameters"]["subnetId"]
        return "location", "unknown"

    def fields(self):
        location, location_value = self.get_location()
        return [{
            "user": self.user,
            "instance type": self.msg["requestParameters"]["instanceType"],
            location: location_value
        }]

    def failure_fields(self):
        location, location_value = self.get_location()
        return [self.default_failure_fields,
                {"instance type": self.msg["requestParameters"]["instanceType"],
                 location: location_value}]

    def success_title(self):
        return "{} new instances were launched".format(len(self.instances))

    def failure_title(self):
        return "Failed to launch instances"

    def success_text(self):
        return "The following instances were launched:\n" + \
            ("\n".join(self.instances))

    def failure_text(self):
        return "Requested instances:\n"+("\n".join(self.instances))


class CreateSnapshotFormatter(MessageFormatter):

    def success_title(self):
        return "EBS snapshot created"

    def fields(self):
        return [{
            "user": self.user,
            "volume": self.msg["requestParameters"]["volumeId"],
            "snapshot": self.msg["responseElements"]["snapshotId"]
        }]

    def failure_fields(self):
        return [self.default_failure_fields, {
            "volume": self.msg["requestParameters"]["volumeId"]
        }]


class DeleteDBInstanceFormatter(MessageFormatter):

    def build(self):
        self.instance = self.msg["requestParameters"]["dBInstanceIdentifier"]

    def success_title(self):
        return "Deleted DB Instance {}".format(self.instance)

    def failure_title(self):
        return "Failed to delete DB instance {}".format(self.instance)

    def color(self):
        return "danger"

    def fields(self):
        return [
            {"user": self.user},
            self.msg["requestParameters"]
        ]

    def failure_fields(self):
        return [self.default_failure_fields, self.msg["requestParameters"]]


class ModifyLoadBalancerAttributesFormatter(MessageFormatter):

    def build(self):
        self.lb = self.msg["requestParameters"]["loadBalancerName"]
        self.attrs = self.msg["requestParameters"]["loadBalancerAttributes"]

    def success_title(self):
        return "Modified load balancer attributes"

    def failure_title(self):
        return "Failed to modify load balancer"

    def fields(self):
        return [
            {"user": self.user},
            self.attrs
        ]

    def failure_fields(self):
        return [self.default_failure_fields, self.attrs]


class RegisterInstancesWithLoadBalancerFormatter(MessageFormatter):

    def success_title(self):
        return "{} instances added to load balancer {}".format(
            len(self.instances),
            self.lb)

    def failure_title(self):
        return "Failed to add instances to ELB {}".format(self.lb)

    def success_text(self):
        return "User {} added the following instances to the ELB:\n{}".format(
            self.user,
            "\n".join(self.instances)
        )

    def failure_text(self):
        return "User {} failed to add {} instances to the ELB\nInstances\n:{}".\
            format(self.user, len(self.instances), "\n".join(self.instances))

    def build(self):
        self.lb = self.msg["requestParameters"]["loadBalancerName"]
        self.instances = [
            "* " + instance_name(instance["instanceId"])
            for instance in self.msg["requestParameters"]["instances"]]


class DeleteVolumeFormatter(MessageFormatter):

    def success_title(self):
        return "Volume deleted"

    def failure_title(self):
        return "Failed to delete volume"

    def fields(self):
        return [{
            "user": self.user,
            "volume": self.msg["requestParameters"]["volumeId"]
        }]

    def failure_fields(self):
        return [
            self.default_failure_fields,
            {"volume": self.msg["requestParameters"]["volumeId"]}
        ]


class ModifyInstanceAttributeFormatter(MessageFormatter):

    def success_text(self):
        return "Instance attributes modified"

    def failure_text(self):
        return "Failed to modify instance attributes"

    @property
    def attrs(self):
        atts = {}
        for p, v in self.msg["requestParameters"].items():
            if p == "instanceId":
                atts[p] = instance_name(v)
            else:
                atts[p] = v["value"]

        return atts

    def fields(self):
        return [
            {"user": self.user},
            self.attrs
        ]

    def failure_fields(self):
        return[
            self.default_failure_fields,
            self.attrs
        ]


class StopInstancesFormatter(MessageFormatter):

    def success_title(self):
        return "{} instances stopped".format(len(self.instances))

    def failure_title(self):
        return "Failed to stop {} instancs".format(len(self.instances))

    def success_text(self):
        return "{} {}stopped the following instances:\n{}".format(
            self.user,
            ("force " if self.msg["requestParameters"]["force"] else ""),
            "\n".join(self.instances))

    def failure_text(self):
        return "{} attempted to {}stop the following instances:\n{}".format(
            self.user,
            ("force " if self.msg["requestParameters"]["force"] else ""),
            "\n".join(self.instances))

    def build(self):
        self.instances = []
        if self.response is not None:
            for instance in self.response["instancesSet"]["items"]:
                self.instances.append("* {} (was {})".format(
                    instance_name(instance["instanceId"]),
                    instance["previousState"]["name"]
                ))
        else:
            for instance in self.request["instancesSet"]["items"]:
                self.instances.append("* "+instance["instanceId"])


class SecurityGroupsModifiedFormatter(MessageFormatter):

    def success_title(self):
            return "Security Groups updated on {}".format(self.interface_name)

    def failure_title(self):
            return "Failed to modify security groups on {}".format(
                self.interface_name)

    def success_text(self):
        return "User {} updated groups to:\n{}".format(
            self.user,
            "\n".join(self.groups))

    def failure_text(self):
        return "User {} attempted to update groups t:\n{}".format(
            self.user,
            "\n".join(self.groups))

    def build(self):
        interface_id = self.request["networkInterfaceId"]
        interface = inv.get_network_interface(interface_id)
        self.interface_name = interface["name"] if interface else interface_id
        self.groups = ["* "+group_name(g["groupId"])
                       for g in self.request["groupSet"]["items"]]


class NetworkInterfaceModifiedFormatter(MessageFormatter):

    def success_title(self):
        return "Network interface {} updated".format(self.interface_name)

    def failure_title(self):
        return "Failed to modify network interface {}".format(
            self.interface_name)

    def fields(self):
        return [
            {"user": self.user},
            self.request
        ]

    def build(self):
        interface_id = self.request["networkInterfaceId"]
        interface = inv.get_network_interface(interface_id)
        self.interface_name = interface["name"] if interface else interface_id


class ModifyNetworkInterfaceAttributeFormatter(MessageFormatter):

    def is_sg_modification(self):
        return "groupSet" in self.request

    def build(self):
        if self.is_sg_modification():
            self.inner = SecurityGroupsModifiedFormatter(self.msg)
        else:
            self.inner = NetworkInterfaceModifiedFormatter(self.msg)
        self.inner.build()

    def format(self):
        return self.inner.format()


class StartInstancesFormatter(MessageFormatter):

    def success_title(self):
        return "Started {} instance(s)".format(self.instance_count)

    def failure_title(self):
        return "Failed to start {} instances".format(self.instance_count)

    def success_text(self):
        return "User {} started the following instances:\n{}".format(
            self.user,
            "\n".join(self.instances))

    def failure_text(self):
        return "User {} attempted to start the following instances:\n{}".format(
            self.user,
            "\n".join(self.instances))

    def build(self):
        if self.response:
            self.instances = ["* {} (was {})".format(
                              i["instanceId"],
                              i["previousState"]["name"]
                              )
                              for i in self.response["instancesSet"]["items"]]
        else:
            self.instances = ["* "+i["instanceId"]
                              for i in self.request["instancesSet"]["items"]]
        self.instance_count = len(self.instances)


class AuthorizeSecurityGroupIngressFormatter(MessageFormatter):

    def success_title(self):
        return "Security group inbound rule modified"

    def success_text(self):
        return "User {} updated the group {}. New ruleset follows:\n{}".format(
            self.user,
            group_name(self.groupid),
            self.format_group()
        )

    def failure_title(self):
        return "Failed to update security group"

    def failure_text(self):
        return "User {} failed to update the group {}\
                with the following rules:\n{}".format(
            self.user,
            group_name(self.groupid),
            self.format_group()
        )

    def format_group(self):
        group = []
        for p in self.request["ipPermissions"]["items"]:
            rule = []
            proto, fromport, toport = p["ipProtocol"], p["fromPort"], p["toPort"]
            if fromport == toport:
                rule.append("*port {} {}*".format(fromport, proto))
            else:
                rule.append("*ports {}-{} {}*".format(fromport, toport, proto))
            rule.append("Allowed from:")

            if "items" in p["groups"]:
                for g in p["groups"]["items"]:
                    rule.append("* "+group_name(g["groupId"]))

            if "items" in p["ipRanges"]:
                for r in p["ipRanges"]["items"]:
                    rule.append("* "+r["cidrIp"])
            group.append("\n".join(rule))
        return "\n".join(group)

    def build(self):
        self.groupid = self.request["groupId"]


class RevokeSecurityGroupIngressFormatter(AuthorizeSecurityGroupIngressFormatter):
    pass


class CreateUserFormatter(MessageFormatter):

    def success_title(self):
        return "New user {} added".format(self.username)

    def failure_title(self):
        return "Failed to create new user {}".format(self.username)

    def build(self):
        self.username = self.request["userName"]

    def fields(self):
        return [{
            "Created by": self.user
        }]


class AddUserToGroupFormatter(MessageFormatter):

    def success_title(self):
        return "{} was added to group {}".format(self.username, self.groupname)

    def failure_title(self):
        return "Failed to add {} to group {}".format(self.username, self.groupname)

    def fields(self):
        return [{"Added by":self.user}]

    def build(self):
        self.username = self.request["userName"]
        self.groupname = self.request["groupName"]


class DeregisterInstancesFromLoadBalancerFormatter(MessageFormatter):

    def success_title(self):
        return "Removed {} instances from ELB {}".format(
            self.instance_count,
            self.elb
        )

    def failure_title(self):
        return "Failed while removing {} instances from ELB {}".format(
            self.instance_count,
            self.elb
        )

    def build(self):
        self.elb = self.request["loadBalancerName"]
        self.instances = [instance_name(i["instanceId"])
                                        for i in self.request["instances"]]
        self.instance_count = len(self.instances)

    def success_text(self):
        return "{} removed the following instances:\n{}".format(
            self.user,
            "\n".join(self.instances)
        )

    def failure_text(self):
        return "{} attempted to remove the following instances:\n{}".format(
            self.user,
            "\n".join(self.instances)
        )


class CreateSecurityGroupFormatter(MessageFormatter):

    def success_title(self):
        return "Created security group {}".format(
            self.groupname
        )

    def failure_title(self):
        return "Failed to create security group {}".format(
            self.groupname
        )

    def success_fields(self):
        return [{
            "user": self.user,
            "group": self.groupname,
            "description": self.request["groupDescription"],
            "vpc": self.request["vpcId"]
        }]

    def build(self):
        self.groupname = self.request["groupName"]
        if self.response:
            id = self.response["groupId"]
            inv.add_group(id, self.groupname)


class UploadServerCertificateFormatter(MessageFormatter):

    def success_title(self):
        return "New server cerificate uploaded"

    def fields(self):
        return [{
            "user": self.user,
            "cert": self.request["serverCertificateName"],
            "arn": self.response["serverCertificateMetadata"]["arn"]
        }]

    def failure_title(self):
        return "Failed to upload a server certificate"

    def failure_fields(self):
        return[self.default_failure_fields, {
            "cert": self.request["serverCertificateName"],
        }]


class DeleteLoadBalancerListenersFormatter(MessageFormatter):

    def success_title(self):
        return "Load balancer {} listeners deleted".format(self.elb)

    def failure_title(self):
        return "Failed to remove listeners on {}".format(self.elb)

    def success_text(self):
        return "{} removed the following port(s): ".format(
            self.user,
            self.ports
            )

    def failure_text(self):
        return "{} attempted to remove the following port(s): ".format(
            self.user,
            self.ports
        )

    def build(self):
        self.ports = ["* {}".format(p)
                      for p in self.request["loadBalancerPorts"]]

        self.elb = self.request["loadBalancerName"]


class CreateLoadBalancerListenersFormatter(MessageFormatter):

    def success_title(self):
        return "Load balancer {} listeners added".format(self.elb)

    def failure_title(self):
        return "Failed to add listeners to ELB {}".format(self.elb)

    def success_text(self):
        return "{} added the following port(s): ".format(
            self.user,
            self.ports
            )

    def failure_text(self):
        return "{} attempted to remove the following port(s): ".format(
            self.user,
            self.ports
        )

    def build(self):
        self.ports = ["* {}=>{} ({})".format(
                        p["loadBalancerPort"],
                        p["instancePort"],
                        p["instanceProtocol"])
                      for p in self.request["listeners"]]
        self.elb = self.request["loadBalancerName"]


class CreateAccessKeyFormatter(MessageFormatter):

    def success_title(self):
        return "New access key created for {}".format(self.username)

    def failure_text(self):
        return "Failed to create access key for {}".format(self.username)

    def success_text(self):
        return "{} created a new access key with id {}".format(
            self.user,
            self.access_key_id
        )

    def build(self):
        self.username = self.request["userName"]
        if self.response:
            self.access_key_id = self.response["accessKey"]["accessKeyId"]


class CreateDBSnapshotFormatter(MessageFormatter):

    def success_title(self):
        return "Snapshot created for {}".format(self.instance)

    def failure_title(self):
        return "Failed to take snapshot for {}".format(self.instance)

    def fields(self):
        return[{
            "snapshot": self.response["dBSnapshotIdentifier"],
            "type": self.response["snapshotType"],
            "user": self.user
        }]

    def build(self):
        self.instance = self.request["dBInstanceIdentifier"]


class UpdateLoginProfileFormatter(MessageFormatter):

    def success_title(self):
        return "Password changed for user {}".format(self.username)

    def failure_title(self):
        return "Failed to change password for {}".format(self.username)

    def fields(self):
        return [
            {"changed by": self.user},
            self.request
        ]

    def failure_fields(self):
        return [self.default_failure_fields, self.request]

    def build(self):
        self.username = self.request["userName"]


class EnableMFADeviceFormatter(MessageFormatter):

    def success_title(self):
        return "MFA device added for {}".format(self.username)

    def failure_title(self):
        return "Failed to enable MFA device for {}".format(self.username)

    def build(self):
        self.username = self.request["userName"]


class AcceptVpcPeeringConnectionFormatter(MessageFormatter):

    def success_title(self):
        return "New VPC peering connection accepted"

    def failure_title(self):
        return "Failed to accept a VPC peering connection request"

    def fields(self):
        return [{
            "user": self.user,
            "from": "{}/{} (cidr: {})".format(
                self.requester["ownerId"],
                self.requester["vpcId"],
                self.requester["cidrBlock"]
            ),
            "to": "{}/{} (cidr: {})".format(
                self.accepter["ownerId"],
                self.accepter["vpcId"],
                self.accepter["cidrBlock"]
            )
        }]

    def build(self):
        if self.response:
            self.accepter = self.response["vpcPeeringConnection"]["accepterVpcInfo"]
            self.requester = self.response["vpcPeeringConnection"]["requesterVpcInfo"]
        self.vpc_pxid = self.request["vpcPeeringConnectionId"]



class ConfigureHealthCheckFormatter(MessageFormatter):

    def success_title(self):
        return "Health check configured on {}".format(self.elb)

    def failure_title(self):
        return "Failed to configure health check on {}".format(self.elb)

    def build(self):
        self.elb = self.request["loadBalancerName"]

    def fields(self):
        return [
                {"user":self.user},
                self.request["healthCheck"]
        ]

    def failure_fields(self):
        return [
                self.default_failure_fields,
                self.request["healthCheck"]
        ]


class RebootInstancesFormatter(MessageFormatter):

    def success_title(self):
        return "{} instances rebooted".format(
            self.instance_count
        )

    def failure_title(self):
        return "Failed while restarting {} instances".format(
            self.instance_count
        )

    def success_text(self):
        return "{} rebooted the following instances:\n{}".format(
            self.user,
            "\n".join(self.instances)
        )


    def build(self):
        self.instances = ["* "+instance_name(i["instanceId"])
                          for i in self.request["instancesSet"]["items"]
                          ]
        self.instance_count = len(self.instances)


class ConsoleLoginFormatter(MessageFormatter):

    def failure_fields(self):
        return [self.default_failure_fields, self.msg["additionalEventData"]]

    def failure_title(self):
        return "Console login failure"

    def format(self):
        if "errorMessage" in self.msg:
            return MessageFormatter.format(self)
        return None


class CreateLoginProfileFormatter(MessageFormatter):

    def success_title(self):
        return "Login profile created"

    def fields(self):
        return [self.response['loginProfile'], {'user': self.user}]

    def failure_title(self):
        return "Failed to create login profile"

    def failure_fields(self):
        return [self.default_failure_fields, self.request]


class SetLoadBalancerPoliciesOfListenerFormatter(MessageFormatter):

    def success_title(self):
        return "Load balancer listener policies updated"

    def failure_title(self):
        return "Failed to update load balancer policies"

    def fields(self):
        return [{
            'user':self.user,
            'loadbalancer': self.loadbalancer,
            'groups': self.groups
        }]

    def failure_fields(self):
        return [
                self.default_failure_fields,
                {
                    'loadbalancer': self.loadbalancer,
                    'groups': self.groups
                }]

    def build(self):
        self.loadbalancer = '{}:{}'.format(
            self.request['loadBalancerName'],
            self.request['loadBalancerPort']
        )
        self.groups = ', '.join(self.request['policyNames'])


class CreateVirtualMFADeviceFormatter(MessageFormatter):

    def success_title(self):
        return "Virtual MFA device added for"+self.user

    def failure_title(self):
        return "Failed to create virtual MFA device"


class PutBucketAclFormatter(MessageFormatter):

    def success_title(self):
        return "Bucket ACL updated for "+self.bucket

    def failure_title(self):
        return "Failed to update ACL for bucket"+self.bucket

    def fields(self):
        return [{'user': self.user}]

    def build(self):
        self.bucket = self.request['bucketName']


class PutRolePolicyFormatter(MessageFormatter):

    def success_title(self):
        return "Role policy updated"

    def failure_title(self):
        return "Failed to update role policy"

    def success_text(self):
        return "{} edited the inline policy {} on the role {}\n```{}```".format(
            self.user,
            self.policy,
            self.role,
            format_policy(self.request["policyDocument"])
        )

    def failure_text(self):
        return "{} attempted to edit the inline policy {} on the role {\n```{}```}".format(
            self.user,
            self.policy,
            self.role,
            format_policy(self.request["policyDocument"])
        )

    def build(self):
        self.role = self.request['roleName']
        self.policy = self.request['policyName']


class CreateRoleFormatter(MessageFormatter):

    def success_title(self):
        return "{} created the role {}".format(self.user, self.role)

    def failure_title(self):
        return "{} failed to create the role {}".format(self.user, self.role)

    def build(self):
        self.role = self.request['roleName']


class PutBucketPolicyFormatter(MessageFormatter):

    def success_title(self):
        return "{} updated policy for the bucket {}".format(
            self.user,
            self.bucket
        )

    def failure_title(self):
        return "{} failed to update  policy for the bucket {}".format(
            self.user,
            self.bucket
        )

    def build(self):
        self.bucket = self.request['bucketName']


class DisableMetricsCollectionFormatter(MessageFormatter):

    def success_title(self):
        return "{} disabled metric collection"

    def failure_title(self):
        return "{} failed to disable metric collection"

    def fields(self):
        return [{'data': self.request}]

    def failure_fields(self):
        return [self.default_failure_fields, self.request]


class AttachRolePolicyFormatter(MessageFormatter):

    def success_title(self):
        return "Role {} updated".format(self.role)

    def failure_title(self):
        return "Failed to update role {}".format(self.role)

    def success_text(self):
        return "{} attached policy `{}` to the role".format(
            self.user,
            self.policy
        )

    def failure_text(self):
        return "{} attempted to attach  policy `{}` to the role".format(
            self.user,
            self.policy
        )

    def build(self):
        self.policy = self.request['policyArn']
        self.role = self.request['roleName']


class AttachUserPolicyFormatter(MessageFormatter):

    def success_title(self):
        return "New policy attached to user {}".format(self.targetuser)

    def failure_title(self):
        return "Failed to attach policy to user {}".format(self.targetuser)

    def success_text(self):
        return "{} attached policy `{}` to the user".format(
            self.user,
            self.policy
        )

    def failure_text(self):
        return "{} attempted to attach  policy `{}` to the user".format(
            self.user,
            self.policy
        )

    def build(self):
        self.policy = self.request['policyArn']
        self.targetuser = self.request['userName']


class PutUserPolicyFormatter(MessageFormatter):

    def success_title(self):
        return "User policy updated"

    def failure_title(self):
        return "Failed to update user policy"

    def success_text(self):
        return "{} attached a policy named {} to {}:\n```{}```".format(
            self.user,
            self.policy,
            self.targetuser,
            format_policy(self.request['policyDocument'])
        )

    def failure_text(self):
        return "{} attempted to attach a policy named {} to {}:\n```{}```".format(
            self.user,
            self.policy,
            self.targetuser,
            format_policy(self.request['policyDocument'])
        )

    def build(self):
        self.policy = self.request['policyName']
        self.targetuser = self.request['userName']


class PutGroupPolicyFormatter(MessageFormatter):

    def success_title(self):
        return "Group policy updated"

    def failure_title(self):
        return "Failed to update group policy"

    def success_text(self):
        return "{} attached a policy named {} to {}:\n```{}```".format(
            self.user,
            self.policy,
            self.targetuser,
            format_policy(self.request['policyDocument'])
        )

    def failure_text(self):
        return "{} attempted to attach a policy named {} to {}:\n```{}```".format(
            self.user,
            self.policy,
            self.targetuser,
            format_policy(self.request['policyDocument'])
        )

    def build(self):
        self.policy = self.request['policyName']
        self.targetuser = self.request['groupName']


class RebootDBInstanceFormatter(MessageFormatter):

    def success_title(self):
        return "DB Instance {} rebooted".format(self.db)

    def failure_title(self):
        return "Failed to reboot db instance "+self.db

    def fields(self):
        return [{'user': self.user, 'failover':self.request['forceFailover']}]

    def build(self):
        self.db = self.request['dBInstanceIdentifier']



class ModifyDBParameterGroupFormatter(MessageFormatter):

    def success_title(self):
        return "DB Parameter group updated"

    def failure_title(self):
        return "Failed to modify DB parameters"

    def fields(self):
        return [{'user': self.user}, self.request]

    def failure_fields(self):
        return [self.default_failure_fields, self.request]


class AttachGroupPolicy(MessageFormatter):

    def success_title(self):
        return "Policy attached to group"

    def failure_title(self):
        return "Failed to attach policy to group"

    def fields(self):
        return [{
            "user": self.user,
            "group": self.request["groupName"],
            "policy": self.request["policyArn"]
        }]

    def failure_fields(self):
        return [self.default_failure_fields,{
            "group": self.request["groupName"],
            "policy": self.request["policyArn"]
        }]


class ApplySecurityGroupsToLoadBalancerFormatter(MessageFormatter):

    def success_title(self):
        return "Security groups updated for ELB "+self.elb

    def failure_title(self):
        return "Failed to updated security groups on ELB "+self.elb

    def success_text(self):
        return "{} added the following security groups:\n{}".format(
            self.user,
            self.groups
        )

    def failure_text(self):
        return "{} failed to add the following security groups:\n{}".format(
            self.user,
            self.groups
        )

    def build(self):
        self.groups = "\n".join([
            "* "+group_name(g) for g in self.request["securityGroups"]
        ])
        self.elb = self.request['loadBalancerName']


class ChangePasswordFormatter(MessageFormatter):

    def success_title(self):
        return "Password updated for {}".format(self.username)

    def failure_title(self):
        return "Failed to change password for {}".format(self.username)

    def success_text(self):
        return "Password updated by {}".format(self.user)

    def build(self):
        self.username = self.request['userName']


class SetLoadBalancerListenerSSLCertificateFormatter(MessageFormatter):

    def success_title(self):
        return "SSL cert updated on ".format(self.elb)

    def failure_title(self):
        return "Failed to update SSL cert on "+self.elb

    def fields(self):
        return [{'user': self.user}]

    def build(self):
        if self.request:
            self.elb = self.request['loadBalancerName']
        else:
            self.elb = ""


class RestoreDBInstanceToPointInTime(MessageFormatter):

    def success_title(self):
        return "{} restored to point-in-time".format(self.db)

    def failure_title(self):
        return "Failed to restore {} to point-in-time"

    def fields(self):
        return [
                {'user':self.user},
                self.request
        ]

    def failure_fields(self):
        return [self.default_failure_fields, self.request]

