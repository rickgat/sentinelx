###############################################################################
# Networking.
#
# Layout (dev, 3 AZs):
#   VPC                  10.42.0.0/16
#   Public subnets       10.42.0.0/24, 10.42.1.0/24, 10.42.2.0/24
#   Private subnets      10.42.16.0/22, 10.42.20.0/22, 10.42.24.0/22
#
# Public subnets host the NAT gateway + ALB.
# Private subnets host EKS nodes, RDS, ElastiCache.
###############################################################################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

# ---------- Public subnets ---------------------------------------------------

resource "aws_subnet" "public" {
  for_each = { for idx, az in local.az_names : idx => az }

  vpc_id                  = aws_vpc.main.id
  availability_zone       = each.value
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, tonumber(each.key))
  map_public_ip_on_launch = true

  tags = {
    Name                                          = "${local.name_prefix}-public-${each.value}"
    "kubernetes.io/role/elb"                      = "1"
    "kubernetes.io/cluster/${local.name_prefix}"  = "shared"
  }
}

# ---------- Private subnets --------------------------------------------------

resource "aws_subnet" "private" {
  for_each = { for idx, az in local.az_names : idx => az }

  vpc_id            = aws_vpc.main.id
  availability_zone = each.value
  # /22 carved out of the 10.42.16.0/20 second half so they never overlap publics.
  cidr_block = cidrsubnet(var.vpc_cidr, 6, tonumber(each.key) + 4)

  tags = {
    Name                                          = "${local.name_prefix}-private-${each.value}"
    "kubernetes.io/role/internal-elb"             = "1"
    "kubernetes.io/cluster/${local.name_prefix}"  = "shared"
  }
}

# ---------- NAT gateway (single, dev) ----------------------------------------

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-nat-eip"
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${local.name_prefix}-nat"
  }

  depends_on = [aws_internet_gateway.main]
}

# ---------- Route tables -----------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${local.name_prefix}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "${local.name_prefix}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}
