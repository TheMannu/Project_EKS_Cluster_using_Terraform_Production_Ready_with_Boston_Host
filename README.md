# Project_EKS_Cluster_using_Terraform_Production_Ready_with_Boston_Host
This repository is Configuring Production Ready EKS Clusters with Terraform and Automating with GitHub Actions. This repository demonstrates the practical steps to set up and automate an EKS cluster. - Infrastructure as Code (IaC): Use Terraform to define and manage EKS cluster. - CI/CD Automation: Leverage GitHub Actions to automate deployments.

# Building a Production-Ready EKS Cluster on AWS with Terraform

## 📋 Project Overview

This guide will walk through creating a a secure, private **Production-ready Amazon EKS (Elastic Kubernetes Service) cluster** using Terraform. Unlike basic public clusters, we'll build a **private, secure cluster** with modular, reusable configuration, proper networking, IAM roles, and security configurations.

### 🎯 What You'll Build
- **Private EKS Cluster** (not publicly accessible)
- **Secure network and Multi-AZ VPC** with public and private subnets across 3 availability zones
- **Proper IAM roles, Security groups and policies**
- **Cost-optimized node groups** (both on-demand and spot instances)
- **Security groups** for controlled access
- **Essential AWS-EKS add-ons** (CNI, CoreDNS, EBS CSI driver)

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
