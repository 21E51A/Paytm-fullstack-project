#vpc creation

resource "aws_vpc" "project-2" {
    cidr_block = "10.0.0.0/16"
    tags = {
      Name="project-2"
    }
}

#subnet creation

resource "aws_subnet" "public-1" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.0.0/24"
    region = "us-east-1a"
    tags = {
       Name="public-1"
    }
}

resource "aws_subnet" "public-2" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.1.0/24"
    region = "us-east-1b"
    tags = {
       Name="public-2"
    }
}

resource "aws_subnet" "private-1" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.2.0/24"
    region = "us-east-1a"
    tags = {
       Name="private-1"
    }
}

resource "aws_subnet" "private-2" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.3.0/24"
    region = "us-east-1b"
    tags = {
       Name="private-2"
    }
}
resource "aws_subnet" "private-3" {
    vpc_id = aws_vpc.project-2.id
    region = "us-east-1a"
    cidr_block = "10.0.4.0/24"
    tags = {
       Name="private-3"
    }
}
resource "aws_subnet" "private-4" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.5.0/24"
    region = "us-east-1b"
    tags = {
       Name="private-4"
    }
}
resource "aws_subnet" "private-5" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.6.0/24"
    region = "us-east-1a"
    tags = {
       Name="private-5"
    }
}

resource "aws_subnet" "private-6" {
    vpc_id = aws_vpc.project-2.id
    cidr_block = "10.0.7.0/24"
    region = "us-east-1b"
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
    route_table_id = aws_route_table.Public-RT
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

#security group creation
#bastion-Host
resource "aws_security_group" "security-group-bastion-host" {
    name = "bastion-host"
    description = "allow"
    vpc_id = aws_vpc.project-2.id 

    # Inbound rules

    ingress  {
        description = "allow"
        from_port = 22
        to_port = 22
        protocol = "ssh"
        cidr_blocks = ["0.0.0.0/0"]
    }
    ingress  {
        description = "allow"
        from_port = 443
        to_port = 443
        protocol = "https"
        cidr_blocks = ["0.0.0.0/0"]
    }
    ingress  {
        description = "allow"
        from_port = 80
        to_port = 80
        protocol = "http"
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

#frontend-sg
resource "aws_security_group" "frontend" {
    name = "frontend"
    description = "allow"
    vpc_id = aws_vpc.project-2.id

  # Inbound rules
  ingress {
    description = "allow"
    from_port = 22
    to_port = 22
    protocol = "tcp"
    security_groups = [aws_security_group.security-group-bastion-host.id]
  }
  
   ingress {
    description      = "Web traffic from Bastion"
    from_port        = 80
    to_port          = 443
    protocol         = "tcp"
    security_groups  = [aws_security_group.security-group-bastion-host.id]
  }

    # Outbound rules
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

#backend-sg
resource "aws_security_group" "backend" {
    name = "backend"
    description = "allow"
    vpc_id = aws_vpc.project-2.id

  # Inbound rules
  ingress {
    description = "allow"
    from_port = 22
    to_port = 22
    protocol = "tcp"
    security_groups = [aws_security_group.security-group-bastion-host.id, aws_security_group.frontend.id]

  }
  
   ingress {
    description      = "Web traffic from Bastion"
    from_port        = 80
    to_port          = 443
    protocol         = "tcp"
    security_groups  = [aws_security_group.security-group-bastion-host.id, aws_security_group.frontend.id]
  }

    # Outbound rules
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

#RDS-sg
resource "aws_security_group" "RDS" {
    name = "RDS"
    description = "allow"
    vpc_id = aws_vpc.project-2.id

  # Inbound rules
  ingress {
    description = "allow"
    from_port = 22
    to_port = 22
    protocol = "tcp"
    security_groups = [aws_security_group.security-group-bastion-host.id, aws_security_group.backend]

  }
  
   ingress {
    description      = "Web traffic from Bastion"
    from_port        = 80
    to_port          = 443
    protocol         = "tcp"
    security_groups  = [aws_security_group.security-group-bastion-host.id, aws_security_group.backend.id]
  }

  ingress {
    description = "allow port 3306"
    from_port = 3306
    to_port = 3306
    protocol = "tcp"
    security_groups = [aws_security_group.backend.id, aws_security_group.security-group-bastion-host.id]

  }

    # Outbound rules
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

#public -sg

resource "aws_security_group" "security-group-public"{
    name = "public"
    description = "allow"
    vpc_id = aws_vpc.project-2.id 

    # Inbound rules
    ingress  {
        description = "allow"
        from_port = 443
        to_port = 443
        protocol = "https"
        cidr_blocks = ["0.0.0.0/0"]
    }
    ingress  {
        description = "allow"
        from_port = 80
        to_port = 80
        protocol = "http"
        cidr_blocks = ["0.0.0.0/0"]
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
