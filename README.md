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
- Go to AWS IAM Console → Users → Create User
- Attach necessary policies (AdministratorAccess for learning, more restricted for production)
- **Note**: For production, use least-privilege principles

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
