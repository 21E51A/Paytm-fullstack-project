#vpc creation

resource "aws_vpc" "project-2" {
    cidr_block = "10.0.0.0/16"

     enable_dns_support   = true
     enable_dns_hostnames = true

    tags = {
      Name="project-2"
    }
}

#subnet creation

resource "aws_subnet" "public-1" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.0.0/24"
    availability_zone = "us-east-1a"
    tags = {
       Name="public-1"
    }
}

resource "aws_subnet" "public-2" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.1.0/24"
    availability_zone = "us-east-1b"
    tags = {
       Name="public-2"
    }
}

resource "aws_subnet" "private-1" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.2.0/24"
    availability_zone = "us-east-1a"
    tags = {
       Name="private-1"
    }
}

resource "aws_subnet" "private-2" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.3.0/24"
    availability_zone = "us-east-1b"
    tags = {
       Name="private-2"
    }
}
resource "aws_subnet" "private-3" {
    vpc_id = aws_vpc.project-2.id
    availability_zone = "us-east-1a"
    cidr_block = "10.0.4.0/24"
    tags = {
       Name="private-3"
    }
}
resource "aws_subnet" "private-4" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.5.0/24"
    availability_zone ="us-east-1b"
    tags = {
       Name="private-4"
    }
}
resource "aws_subnet" "private-5" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.6.0/24"
    availability_zone ="us-east-1a"
    tags = {
       Name="private-5"
    }
}

resource "aws_subnet" "private-6" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.7.0/24"
    availability_zone ="us-east-1b"
    tags = {
       Name="private-6"
    }
}

#internetgateway creation

resource "aws_internet_gateway" "project-IG" {
    vpc_id = aws_vpc.project-2.id
    tags = {
      Name="IG"
    }
}

#route-table-public creation

resource "aws_route_table" "Public-RT" {
    vpc_id = aws_vpc.project-2.id

    route  {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.project-IG.id

    }
    tags = {
      Name="Public-RT"
    }
}

#route-table-assocation-public-creation

resource "aws_route_table_association" "subnet-assoaciation" {
    subnet_id = aws_subnet.public-1.id
    route_table_id = aws_route_table.Public-RT.id
}
resource "aws_route_table_association" "subnet-assoaciation-2" {
    subnet_id = aws_subnet.public-2.id
    route_table_id = aws_route_table.Public-RT.id
}

#elastic-ip creation

resource "aws_eip" "nat_eip" {
    domain = "vpc"
    tags = {
      Name="nat_eip"
    }
}

#NAT gateway creation
resource "aws_nat_gateway" "NAT" {
    allocation_id = aws_eip.nat_eip.id
    subnet_id = aws_subnet.public-1.id
    tags = {
      Name="NAT"
    }
  depends_on = [ aws_internet_gateway.project-IG ]
}

#route-table-private creation
resource "aws_route_table" "private-RT" {
    vpc_id = aws_vpc.project-2.id

    route {
        cidr_block = "0.0.0.0/0"
        nat_gateway_id = aws_nat_gateway.NAT.id

    }
    tags = {
      Name="private-RT"
    }
}

#route-table-assocation-private-creation
resource "aws_route_table_association" "subnet-assoaciation-NAT-1" {
    subnet_id = aws_subnet.private-1.id
    route_table_id = aws_route_table.private-RT.id
}

resource "aws_route_table_association" "subnet-assoaciation-NAT-2" {
    subnet_id = aws_subnet.private-2.id
    route_table_id = aws_route_table.private-RT.id
}
resource "aws_route_table_association" "subnet-assoaciation-NAT-3" {
    subnet_id = aws_subnet.private-3.id
    route_table_id = aws_route_table.private-RT.id
}
resource "aws_route_table_association" "subnet-assoaciation-NAT-4" {
    subnet_id = aws_subnet.private-4.id
    route_table_id = aws_route_table.private-RT.id
}
resource "aws_route_table_association" "subnet-assoaciation-NAT-5" {
    subnet_id = aws_subnet.private-5.id
    route_table_id = aws_route_table.private-RT.id
}
resource "aws_route_table_association" "subnet-assoaciation-NAT-6" {
    subnet_id = aws_subnet.private-6.id
    route_table_id = aws_route_table.private-RT.id
}

##Alb

resource "aws_security_group" "lb_sg" {
  name   = "lb-sg"
  vpc_id = aws_vpc.project-2.id

  
  ingress {
    description = "SSH access from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"          # ✅ FIXED
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"          # ✅ FIXED
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"          # ✅ FIXED
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from anywhere"
    from_port   = 801
    to_port     = 801
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ===============================
# Bastion Host Security Group
# ===============================
resource "aws_security_group" "security-group-bastion-host" {
  name        = "bastion-host"
  description = "Allow SSH and web access for bastion host"
  vpc_id      = aws_vpc.project-2.id

  ingress {
    description = "SSH access from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"          # ✅ FIXED
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"          # ✅ FIXED
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"          # ✅ FIXED
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "bastion-sg"
  }
}

# ===============================
# Frontend Security Group
# ===============================
resource "aws_security_group" "frontend" {
  name        = "frontend"
  description = "Frontend EC2 instance"
  vpc_id      = aws_vpc.project-2.id

  ingress {
    description     = "SSH from Bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.security-group-bastion-host.id]
  }

  ingress {
    description = "Allow HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
   # ✅ Flask / API port (5000) for ALB or Frontend
  ingress {
    description     = "Allow Flask API (port 5000) from ALB and Frontend"
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]  # or restrict to ALB SG later
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "frontend-sg"
  }
}

# ===============================
# Backend Security Group
# ===============================
resource "aws_security_group" "backend" {
  name        = "backend"
  description = "Backend EC2 instance"
  vpc_id      = aws_vpc.project-2.id

  ingress {
    description     = "SSH from Bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.security-group-bastion-host.id, aws_security_group.lb_sg.id]  # on ALB
  }

  ingress {
    description     = "Web traffic from Frontend"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend.id]
  }

  ingress {
    description     = "HTTPS from Frontend"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend.id]
  }

  # ✅ Flask / API port (5000) for ALB or Frontend
  ingress {
    description     = "Allow Flask API (port 5000) from ALB and Frontend"
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]  # or restrict to ALB SG later
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "backend-sg"
  }
}

# ===============================
# RDS Security Group
# ===============================
resource "aws_security_group" "rds-sg" {
  name        = "rds-sg"
  description = "Allow MySQL access for debugging"
  vpc_id      = aws_vpc.project-2.id

  ingress {
    description = "Temporary MySQL access"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "rds-sg"
  }
}


# ===============================
# Public Security Group
# ===============================
resource "aws_security_group" "security-group-public" {
  name        = "public"
  description = "Allow public web access"
  vpc_id      = aws_vpc.project-2.id

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 # ✅ Flask / API port (5000) for ALB or Frontend
  ingress {
    description     = "Allow Flask API (port 5000) from ALB and Frontend"
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]  # or restrict to ALB SG later
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "public-sg"
  }
}

#server creation
# 1️⃣ Bastion Host (Public Subnet)

resource "aws_instance" "baston_host" {
  ami = "ami-0157af9aea2eef346"
  instance_type = "t3.micro"
  key_name = "mynewkeypair"
  vpc_security_group_ids = [aws_security_group.security-group-bastion-host.id]
  subnet_id = aws_subnet.public-1.id
  associate_public_ip_address = true
  tags = {
    Name="bastion-host"
  }
}

#frontend server

resource "aws_instance" "frontend" {
  ami = "ami-0157af9aea2eef346"
  instance_type = "t3.micro"
  key_name = "mynewkeypair"
  vpc_security_group_ids = [aws_security_group.frontend.id]
  subnet_id = aws_subnet.private-1.id
  associate_public_ip_address = false
  tags = {
    Name="frontend"
  }
}

#backend server


resource "aws_instance" "backend" {
  ami = "ami-0157af9aea2eef346"
  instance_type = "t3.micro"
  key_name = "mynewkeypair"
  vpc_security_group_ids = [aws_security_group.backend.id]
  subnet_id = aws_subnet.private-2.id
  associate_public_ip_address = false
  tags = {
    Name="backend"
  }
}

#Database creation
#rds-subnet-group creation
resource "aws_db_subnet_group" "rds-subnet-group" {
  name = "rds-subnet-group"
  subnet_ids = [ aws_subnet.private-3.id, aws_subnet.private-4.id ]

  tags = {
    Name="rds-subnet-group"
  }
}
# RDS Instance
resource "aws_db_instance" "rds" {
  identifier              = "rds"
  allocated_storage       = 20
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  db_name                 = "rds"
  username                = "admin"
  password                = "Admin123"   # ⚠️ Change this in production
  parameter_group_name    = "default.mysql8.0"
  skip_final_snapshot     = true
  publicly_accessible     = true

  # Attach RDS Security Group
  vpc_security_group_ids = [
    aws_security_group.rds-sg.id
  ]

  # Subnet group (can use public or private)
  db_subnet_group_name = aws_db_subnet_group.rds-subnet-group.id

  tags = {
    Name = "rds"
  }

  depends_on = [
    aws_vpc.project-2,
    aws_nat_gateway.NAT,
    aws_security_group.rds-sg
  ]
}


# ===============================
# S3 Bucket Creation
# ===============================

resource "aws_s3_bucket" "project_bucket" {
  bucket = "paytm-fullstack-bucket-akash-nov2025"  # must be globally unique
  tags = {
    Name = "project-bucket"
    Environment = "Dev"
  }
}

# Enable versioning for backup safety
resource "aws_s3_bucket_versioning" "project_bucket_versioning" {
  bucket = aws_s3_bucket.project_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption for security
resource "aws_s3_bucket_server_side_encryption_configuration" "project_bucket_encryption" {
  bucket = aws_s3_bucket.project_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# (Optional) Public access block (recommended for private data)
resource "aws_s3_bucket_public_access_block" "project_bucket_block" {
  bucket = aws_s3_bucket.project_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
