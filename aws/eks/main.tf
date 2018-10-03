provider "aws" {
    region = "us-west-2"
}

variable "cluster-name" {
  default = "tf-eks-yeoldebrewery"
  type    = "string"
}

# This data source is included for ease of sample architecture deployment
# and can be swapped out as necessary.
data "aws_availability_zones" "available" {}

resource "aws_vpc" "yeoldebrewery" {
  cidr_block = "10.0.0.0/16"

  tags = "${
    map(
     "Name", "tf-eks-yeoldebrewery-node",
     "kubernetes.io/cluster/${var.cluster-name}", "shared",
    )
  }"
}

resource "aws_subnet" "yeoldebrewery" {
  count = 2

  availability_zone = "${data.aws_availability_zones.available.names[count.index]}"
  cidr_block        = "10.0.${count.index}.0/24"
  vpc_id            = "${aws_vpc.yeoldebrewery.id}"

  tags = "${
    map(
     "Name", "tf-eks-yeoldebrewery-node",
     "kubernetes.io/cluster/${var.cluster-name}", "shared",
    )
  }"
}

resource "aws_internet_gateway" "yeoldebrewery" {
  vpc_id = "${aws_vpc.yeoldebrewery.id}"

  tags {
    Name = "tf-eks-yeoldebrewery"
  }
}

resource "aws_route_table" "yeoldebrewery" {
  vpc_id = "${aws_vpc.yeoldebrewery.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.yeoldebrewery.id}"
  }
}

resource "aws_route_table_association" "yeoldebrewery" {
  count = 2

  subnet_id      = "${aws_subnet.yeoldebrewery.*.id[count.index]}"
  route_table_id = "${aws_route_table.yeoldebrewery.id}"
}

resource "aws_iam_role" "yeoldebrewery-cluster" {
  name = "tf-eks-yeoldebrewery-cluster"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "yeoldebrewery-cluster-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = "${aws_iam_role.yeoldebrewery-cluster.name}"
}

resource "aws_iam_role_policy_attachment" "yeoldebrewery-cluster-AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = "${aws_iam_role.yeoldebrewery-cluster.name}"
}

resource "aws_security_group" "yeoldebrewery-cluster" {
  name        = "tf-eks-yeoldebrewery-cluster"
  description = "Cluster communication with worker nodes"
  vpc_id      = "${aws_vpc.yeoldebrewery.id}"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags {
    Name = "tf-eks-yeoldebrewery"
  }
}

# OPTIONAL: Allow inbound traffic from your local workstation external IP
#           to the Kubernetes. You will need to replace A.B.C.D below with
#           your real IP. Services like icanhazip.com can help you find this.
resource "aws_security_group_rule" "yeoldebrewery-cluster-ingress-workstation-https" {
  cidr_blocks       = ["67.207.104.155/32"]
  description       = "Allow workstation to communicate with the cluster API Server"
  from_port         = 443
  protocol          = "tcp"
  security_group_id = "${aws_security_group.yeoldebrewery-cluster.id}"
  to_port           = 443
  type              = "ingress"
}

resource "aws_eks_cluster" "yeoldebrewery" {
  name            = "${var.cluster-name}"
  role_arn        = "${aws_iam_role.yeoldebrewery-cluster.arn}"

  vpc_config {
    security_group_ids = ["${aws_security_group.yeoldebrewery-cluster.id}"]
    subnet_ids         = ["${aws_subnet.yeoldebrewery.*.id}"]
  }

  depends_on = [
    "aws_iam_role_policy_attachment.yeoldebrewery-cluster-AmazonEKSClusterPolicy",
    "aws_iam_role_policy_attachment.yeoldebrewery-cluster-AmazonEKSServicePolicy",
  ]
}

locals {
  kubeconfig = <<KUBECONFIG


apiVersion: v1
clusters:
- cluster:
    server: ${aws_eks_cluster.yeoldebrewery.endpoint}
    certificate-authority-data: ${aws_eks_cluster.yeoldebrewery.certificate_authority.0.data}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: aws
  name: aws
current-context: aws
kind: Config
preferences: {}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws-iam-authenticator
      args:
        - "token"
        - "-i"
        - "${var.cluster-name}"
KUBECONFIG
}

output "kubeconfig" {
  value = "${local.kubeconfig}"
}

resource "aws_iam_role" "yeoldebrewery-node" {
  name = "tf-eks-yeoldebrewery-node"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "yeoldebrewery-node-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = "${aws_iam_role.yeoldebrewery-node.name}"
}

resource "aws_iam_role_policy_attachment" "yeoldebrewery-node-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = "${aws_iam_role.yeoldebrewery-node.name}"
}

resource "aws_iam_role_policy_attachment" "yeoldebrewery-node-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = "${aws_iam_role.yeoldebrewery-node.name}"
}

resource "aws_iam_instance_profile" "yeoldebrewery-node" {
  name = "tf-eks-yeoldebrewery"
  role = "${aws_iam_role.yeoldebrewery-node.name}"
}

resource "aws_security_group" "yeoldebrewery-node" {
  name        = "tf-eks-yeoldebrewery-node"
  description = "Security group for all nodes in the cluster"
  vpc_id      = "${aws_vpc.yeoldebrewery.id}"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = "${
    map(
     "Name", "tf-eks-yeoldebrewery-node",
     "kubernetes.io/cluster/${var.cluster-name}", "owned",
    )
  }"
}

resource "aws_security_group_rule" "yeoldebrewery-node-ingress-self" {
  description              = "Allow node to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = "${aws_security_group.yeoldebrewery-node.id}"
  source_security_group_id = "${aws_security_group.yeoldebrewery-node.id}"
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "yeoldebrewery-node-ingress-cluster" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  from_port                = 1025
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.yeoldebrewery-node.id}"
  source_security_group_id = "${aws_security_group.yeoldebrewery-cluster.id}"
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "yeoldebrewery-cluster-ingress-node-https" {
  description              = "Allow pods to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.yeoldebrewery-cluster.id}"
  source_security_group_id = "${aws_security_group.yeoldebrewery-node.id}"
  to_port                  = 443
  type                     = "ingress"
}

data "aws_ami" "eks-worker" {
  filter {
    name   = "name"
    values = ["amazon-eks-node-v*"]
  }

  most_recent = true
  owners      = ["602401143452"] # Amazon Account ID
}

# This data source is included for ease of sample architecture deployment
# and can be swapped out as necessary.
data "aws_region" "current" {}

# EKS currently documents this required userdata for EKS worker nodes to
# properly configure Kubernetes applications on the EC2 instance.
# We utilize a Terraform local here to simplify Base64 encoding this
# information into the AutoScaling Launch Configuration.
# More information: https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html
locals {
  yeoldebrewery-node-userdata = <<USERDATA
#!/bin/bash
set -o xtrace
/etc/eks/bootstrap.sh --apiserver-endpoint '${aws_eks_cluster.yeoldebrewery.endpoint}' --b64-cluster-ca '${aws_eks_cluster.yeoldebrewery.certificate_authority.0.data}' '${var.cluster-name}'
USERDATA
}

resource "aws_launch_configuration" "yeoldebrewery" {
  associate_public_ip_address = true
  iam_instance_profile        = "${aws_iam_instance_profile.yeoldebrewery-node.name}"
  image_id                    = "${data.aws_ami.eks-worker.id}"
  instance_type               = "m4.large"
  name_prefix                 = "tf-eks-yeoldebrewery"
  security_groups             = ["${aws_security_group.yeoldebrewery-node.id}"]
  user_data_base64            = "${base64encode(local.yeoldebrewery-node-userdata)}"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "yeoldebrewery" {
  desired_capacity     = 2
  launch_configuration = "${aws_launch_configuration.yeoldebrewery.id}"
  max_size             = 2
  min_size             = 1
  name                 = "tf-eks-yeoldebrewery"
  vpc_zone_identifier  = ["${aws_subnet.yeoldebrewery.*.id}"]

  tag {
    key                 = "Name"
    value               = "tf-eks-yeoldebrewery"
    propagate_at_launch = true
  }

  tag {
    key                 = "kubernetes.io/cluster/${var.cluster-name}"
    value               = "owned"
    propagate_at_launch = true
  }
}

locals {
  config-map-aws-auth = <<CONFIGMAPAWSAUTH


apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: ${aws_iam_role.yeoldebrewery-node.arn}
      username: system:node:{{EC2PrivateDNSName}}
      groups:
        - system:bootstrappers
        - system:nodes
CONFIGMAPAWSAUTH
}

output "config-map-aws-auth" {
  value = "${local.config-map-aws-auth}"
}


