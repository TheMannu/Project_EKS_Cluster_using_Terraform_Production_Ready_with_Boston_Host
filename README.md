# Project_EKS_Cluster_using_Terraform_Production_Ready_with_Boston_Host
This repository is Configuring Production Ready EKS Clusters with Terraform and Automating with GitHub Actions. This repository demonstrates the practical steps to set up and automate an EKS cluster. - Infrastructure as Code (IaC): Use Terraform to define and manage EKS cluster. - CI/CD Automation: Leverage GitHub Actions to automate deployments.

# Building a Production-Ready EKS Cluster on AWS with Terraform

## 📋 Project Overview

This guide will walk through creating a a secure, private **Production-ready Amazon EKS (Elastic Kubernetes Service) cluster** using Terraform. Unlike basic public clusters, we'll build a **private, secure cluster** with modular, reusable configuration, proper networking, IAM roles, and security configurations.

### 🎯 What You'll Build
- **Private EKS Cluster** (not publicly accessible)
- **Secure network and Multi-AZ VPC** with public and private subnets across 3 availability zones
- **Proper IAM roles, Security groups and policies**
- **Cost-optimized node groups** A mix of **On-Demand** and **Spot Instance** node groups.
- **Security groups** for controlled access
- **Essential AWS-EKS add-ons** (CNI, CoreDNS, EBS CSI driver)
- **Infrastructure as Code (IaC):** Entirely built using **Terraform** with a **modular structure** for reusability.
- **Secure Access:** Cluster access is restricted via a ** Security Group** to a designated **Jump Server (Bastion Host)**

---

| What you get at the end | What you pay (if you clean up) |
|-------------------------|--------------------------------|
| 1 VPC, 3 AZs, 6 subnets, 1 private EKS, 2 managed node-groups (on-demand + spot), all add-ons, S3 remote state | ≈ 0.50 USD for 1 h |

---

## 🛠 Prerequisites & Tools Setup

### Required Tools
1. **Terraform** (version 1.9.3 or later)
2. **AWS CLI**
3. **kubectl** (Kubernetes command-line tool)
4. **AWS Account** with appropriate permissions

### Installation Steps

#### 1. Install AWS CLI
```bash
# On Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify installation
aws --version
```

#### 2. Install Terraform
```bash
# On Linux
wget https://releases.hashicorp.com/terraform/1.5.7/terraform_1.5.7_linux_amd64.zip
unzip terraform_1.5.7_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# Verify installation
terraform version
```

#### 3. Install kubectl
```bash
# On Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Verify installation
kubectl version --client
```

### AWS Configuration

#### 1. Create IAM User with Appropriate Permissions
- Go to AWS Console → IAM → Users → **Add users**
  Name: `eks-admin`
- Attach necessary policies (AdministratorAccess for learning, more restricted for production)
  Permission: **PowerUserAccess** (or `AdministratorAccess` on your private account) 
- **Note**: For production, use least-privilege principles
- **Security credentials → Create access key**  
  Save the two strings (`AKIA…` & `…secret…`) – you get them **only once**.

#### 2. Configure AWS Credentials
```bash
aws configure
```
Enter your:
- AWS Access Key ID
- AWS Secret Access Key
- Default region (e.g., `us-east-1`)
- Default output format (e.g., `json`)

#### 3. Verify AWS Configuration
```bash
aws sts get-caller-identity
```


#### 4.Create the S3 Bucket for State
Terraform must remember what it built; we store that memory in S3.

```bash
# bucket names are GLOBAL – pick a unique one
aws s3 mb s3://my-eks-terraform-state-12345 --region us-east-1
# turn on versioning (cheap insurance)
aws s3api put-bucket-versioning --bucket my-eks-terraform-state-12345 \
      --versioning-configuration Status=Enabled
```

Edit `backend.tf` and replace the bucket name with yours.

---

## 🏗 Project Structure

Create the following directory structure:
```
eks-project/
├── modules/
│   ├── vpc.tf
│   ├── iam.tf
│   ├── eks.tf
│   └── data.tf
├── eks/
|   ├── main.tf            # use the module
|   ├── variables.tf       # declarations
|   ├── dev.tfvars         # YOUR values
|   ├── backend.tf         # remote state lock
|   └── README.md         
```

---

## 📝 Step-by-Step Implementation

### Step 1: Create Backend Configuration (`backend.tf`)

```hcl
terraform {
  required_version = ">= 1.12.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.49.0"
    }
  }

  backend "s3" {
    bucket = "your-terraform-state-bucket"
    key    = "eks/terraform.tfstate"
    region = "us-east-1"
    use_lock_file = true
  }
}

provider "aws" {
  region = var.region
}
```

### Step 2: Create VPC Module (`modules/vpc.tf`)

This module creates the networking layer foundation:

*   **VPC:** The isolated network cloud.
*   **Internet Gateway (IGW):** Provides internet access to resources in public subnets.
*   **NAT Gateway + Elastic IP:** Allows resources in *private* subnets (like worker nodes) to access the internet (e.g., to pull Docker images) while remaining private.
*   **Public & Private Subnets:** Creates them in multiple AZs.
*   **Route Tables:** Configures routes for public (via IGW) and private (via NAT Gateway) subnets.
*   **EKS Cluster Security Group:** Restricts access to the EKS API server (port 443) to only the Jump Server's IP or the VPC CIDR.

```hcl
# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "${var.prefix}-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.prefix}-igw"
  }
}

# Public Subnets
resource "aws_subnet" "public" {
  count                   = var.public_subnet_count
  vpc_id                  = aws_vpc.main.id
  cidr_block              = element(var.public_subnet_cidr_blocks, count.index)
  availability_zone       = element(var.availability_zones, count.index)
  map_public_ip_on_launch = true
  
  tags = {
    Name = "${var.prefix}-public-subnet-${count.index}"
  }
  
  depends_on = [aws_vpc.main]
}

# Private Subnets
resource "aws_subnet" "private" {
  count             = var.private_subnet_count
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(var.private_subnet_cidr_blocks, count.index)
  availability_zone = element(var.availability_zones, count.index)
  
  tags = {
    Name = "${var.prefix}-private-subnet-${count.index}"
  }
}

# NAT Gateway and Elastic IP
resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  
  tags = {
    Name = "${var.prefix}-nat-gw"
  }
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  
  tags = {
    Name = "${var.prefix}-public-rt"
  }
}
 
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  
  tags = {
    Name = "${var.prefix}-private-rt"
  }
}

# Security Group for EKS
resource "aws_security_group" "eks" {
  name_prefix = "${var.prefix}-eks-sg"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr_block] # Restrict to VPC only
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.prefix}-eks-sg"
  }
}
```

### Step 3: Create IAM Module (`modules/iam.tf`)

This module Manages permissions, identities and roles:

*   **EKS Cluster Role:** Grants the EKS service permissions to manage resources on your behalf.
*   **Node Group Role:** Grants permissions to the worker nodes (EC2 instances) to interact with AWS services like ECR and EBS.
*   **Policies:** Attaches necessary policies like `AmazonEKSWorkerNodePolicy`, `AmazonEKS_CNI_Policy`, and `AmazonEC2ContainerRegistryReadOnly`.
*   **OpenID Connect (OIDC) Provider:** Enables IAM Roles for Service Accounts (IRSA), allowing Kubernetes pods to securely call AWS APIs.

```hcl
# Random suffix for unique names
resource "random_integer" "suffix" {
  min = 10000
  max = 99999
}

# EKS Cluster Role
resource "aws_iam_role" "eks_cluster" {
  count = var.cluster_enabled ? 1 : 0
  name  = "${var.prefix}-eks-cluster-role-${random_integer.suffix.result}"
  
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

# Attach EKS Cluster Policy
resource "aws_iam_role_policy_attachment" "eks_cluster" {
  count      = var.cluster_enabled ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster[0].name
}

# Node Group Role
resource "aws_iam_role" "node_group" {
  count = var.node_group_enabled ? 1 : 0
  name  = "${var.prefix}-node-group-role-${random_integer.suffix.result}"
  
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

# Node Group Policies
resource "aws_iam_role_policy_attachment" "node_group" {
  for_each   = var.node_group_enabled ? toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  ]) : []
  policy_arn = each.value
  role       = aws_iam_role.node_group[0].name
}
```

### Step 4: Create EKS Cluster Module (`modules/eks.tf`)

This module creates the Kubernetes cluster and node groups:
The core component that creates and configures the Kubernetes cluster.
*   **EKS Cluster Resource:** Defines the cluster with its version, VPC/Subnet placement, and security settings (private endpoint, public endpoint disabled).
*   **Node Groups:** Creates managed node groups for both On-Demand and Spot instances, specifying instance types, scaling limits, and labels.
*   **Add-ons:** Automatically installs essential Kubernetes add-ons like:
    *   `vpc-cni`: For networking.
    *   `coredns`: For service discovery.
    *   `kube-proxy`: For network proxy.
    *   `aws-ebs-csi-driver`: For dynamic volume provisioning.

```hcl
# EKS Cluster
resource "aws_eks_cluster" "main" {
  count    = var.cluster_enabled ? 1 : 0
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster[0].arn
  version  = var.cluster_version
  
  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.eks.id]
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster
  ]
}

# OpenID Connect Provider
resource "aws_iam_openid_connect_provider" "main" {
  count           = var.cluster_enabled ? 1 : 0
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster[0].certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main[0].identity[0].oidc[0].issuer
}

# EKS Add-ons
resource "aws_eks_addon" "main" {
  for_each          = var.cluster_enabled ? { for addon in var.addons : addon.name => addon } : {}
  cluster_name      = aws_eks_cluster.main[0].name
  addon_name        = each.value.name
  addon_version     = each.value.version
  
  depends_on = [aws_eks_cluster.main]
}

# On-Demand Node Group
resource "aws_eks_node_group" "on_demand" {
  count           = var.on_demand_node_group_enabled ? 1 : 0
  cluster_name    = aws_eks_cluster.main[0].name
  node_group_name = "${var.cluster_name}-on-demand"
  node_role_arn   = aws_iam_role.node_group[0].arn
  subnet_ids      = aws_subnet.private[*].id
  
  capacity_type  = "ON_DEMAND"
  instance_types = var.on_demand_instance_types
  
  scaling_config {
    desired_size = var.on_demand_desired_size
    max_size     = var.on_demand_max_size
    min_size     = var.on_demand_min_size
  }
  
  update_config {
    max_unavailable = 1
  }
  
  labels = {
    "node-type" = "on-demand"
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.node_group
  ]
}

# Spot Node Group
resource "aws_eks_node_group" "spot" {
  count           = var.spot_node_group_enabled ? 1 : 0
  cluster_name    = aws_eks_cluster.main[0].name
  node_group_name = "${var.cluster_name}-spot"
  node_role_arn   = aws_iam_role.node_group[0].arn
  subnet_ids      = aws_subnet.private[*].id
  
  capacity_type  = "SPOT"
  instance_types = var.spot_instance_types
  
  scaling_config {
    desired_size = var.spot_desired_size
    max_size     = var.spot_max_size
    min_size     = var.spot_min_size
  }
  
  update_config {
    max_unavailable = 1
  }
  
  labels = {
    "node-type" = "spot"
  }
}
```

### Step 5: Create Data Sources (`modules/data.tf`)

```hcl
# TLS Certificate for OIDC
data "tls_certificate" "cluster" {
  count   = var.cluster_enabled ? 1 : 0
  url     = aws_eks_cluster.main[0].identity[0].oidc[0].issuer
}

# IAM Policy Document for OIDC
data "aws_iam_policy_document" "oidc_assume_role_policy" {
  count = var.cluster_enabled ? 1 : 0
  
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"
    
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.main[0].identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
    }
    
    principals {
      identifiers = [aws_iam_openid_connect_provider.main[0].arn]
      type        = "Federated"
    }
  }
}
```

### Step 6: Create Main Configuration (`main.tf`)
*   `main.tf`: Calls the modules and passes in variables.

```hcl
locals {
  prefix = "dev-eks"
}

module "eks_cluster" {
  source = "./modules"
  
  # Basic Configuration
  prefix        = local.prefix
  environment   = "dev"
  region        = var.region
  
  # VPC Configuration
  vpc_cidr_block            = var.vpc_cidr_block
  public_subnet_count       = var.public_subnet_count
  private_subnet_count      = var.private_subnet_count
  availability_zones        = var.availability_zones
  public_subnet_cidr_blocks = var.public_subnet_cidr_blocks
  private_subnet_cidr_blocks = var.private_subnet_cidr_blocks
  
  # EKS Configuration
  cluster_enabled    = var.cluster_enabled
  cluster_name       = var.cluster_name
  cluster_version    = var.cluster_version
  endpoint_private_access = var.endpoint_private_access
  endpoint_public_access  = var.endpoint_public_access
  
  # Node Group Configuration
  node_group_enabled        = var.node_group_enabled
  on_demand_node_group_enabled = var.on_demand_node_group_enabled
  spot_node_group_enabled   = var.spot_node_group_enabled
  on_demand_instance_types  = var.on_demand_instance_types
  spot_instance_types       = var.spot_instance_types
  on_demand_desired_size    = var.on_demand_desired_size
  on_demand_max_size        = var.on_demand_max_size
  on_demand_min_size        = var.on_demand_min_size
  spot_desired_size         = var.spot_desired_size
  spot_max_size             = var.spot_max_size
  spot_min_size             = var.spot_min_size
  
  # Add-ons
  addons = var.addons
}
```

### Step 7: Define Variables (`variables.tf`)
*   `variables.tf`: Declares all input variables.

```hcl
variable "region" {
  description = "AWS region"
  type        = string
}

variable "vpc_cidr_block" {
  description = "CIDR block for VPC"
  type        = string
}

variable "public_subnet_count" {
  description = "Number of public subnets"
  type        = number
}

variable "private_subnet_count" {
  description = "Number of private subnets"
  type        = number
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "cluster_version" {
  description = "Kubernetes version"
  type        = string
}

# ... more variables for instance types, scaling, etc.
```

### Step 8: Create Environment Configuration (`dev.tfvars`)
*   `dev.tfvars`: Provides the actual values for the variables (environment-specific configuration).

```hcl
# Environment
environment = "dev"
region      = "us-east-1"

# VPC Configuration
vpc_cidr_block = "10.16.0.0/16"
public_subnet_count = 3
private_subnet_count = 3

availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

public_subnet_cidr_blocks = [
  "10.16.1.0/20",
  "10.16.2.0/20",
  "10.16.3.0/20"
]

private_subnet_cidr_blocks = [
  "10.16.16.0/20",
  "10.16.32.0/20",
  "10.16.48.0/20"
]
