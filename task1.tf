#Login to our profile created: 
provider "aws" {
	region   = "ap-south-1"
	profile  = "aayushi"
}

#Create a key pair:
resource "tls_private_key" mytask_p_key1  {
	algorithm = "RSA"
}

resource "aws_key_pair" "mytask-key1" {
	key_name    = "mytask-key1"
	public_key = tls_private_key.mytask_p_key1.public_key_openssh
}

#create a security group:
resource "aws_security_group" "mytask-sg1" {
	name        = "mytask-sg1"
	description = "Allow TLS inbound traffic"
	vpc_id      = "vpc-31e8f559"

	ingress {
	description = "SSH"
	from_port   = 22
	to_port     = 22
	protocol    = "tcp"
	cidr_blocks = [ "0.0.0.0/0" ]
 }

	ingress {
    	description = "HTTP"
    	from_port   = 80
    	to_port     = 80
    	protocol    = "tcp"
    	cidr_blocks = [ "0.0.0.0/0" ]
 }

	egress {
    	from_port   = 0
    	to_port     = 0
    	protocol    = "-1"
    	cidr_blocks = ["0.0.0.0/0"]
 }

  	tags = {
    	Name = "mytask-sg1"
 }
}

#Launching an EC2 instance using the key-pair and security-group we have created:
resource "aws_instance" "mytask-os1" {
  	ami           = "ami-0447a12f28fddb066"
  	instance_type = "t2.micro"
  	availability_zone = "ap-south-1a"
  	key_name      = "mytask-key1"
  	security_groups = [ "mytask-sg1" ]
 
	connection {
    	type     = "ssh"
    	user     = "ec2-user"
    	private_key =  tls_private_key.mytask_p_key1.private_key_pem
    	host     = aws_instance.mytask-os1.public_ip
 }

 	provisioner "remote-exec" {
    	inline = [
      	"sudo yum install httpd  php git -y",
      	"sudo systemctl restart httpd",
      	"sudo systemctl enable httpd",
       ]
 }

	tags = {
    	Name = "mytask-os1"
 }
}

#Create an EBS volume of size 1 GB:
resource "aws_ebs_volume" "mytask-ebs1" {
  	availability_zone = "ap-south-1a"
  	size              = 1
 
  	tags = {
    	Name = "mytask-ebs1"
 }
}

#Attach the created volume to the launched instance:
resource "aws_volume_attachment" "mytask-attach1" {
 	device_name = "/dev/sdf"
 	volume_id    = "${aws_ebs_volume.mytask-ebs1.id}"
 	instance_id  = "${aws_instance.mytask-os1.id}"
 	force_detach = true
}

#OUTPUT:
output "myos_ip" {
  	value = aws_instance.mytask-os1.public_ip
}	

resource "null_resource" "null_instan_ip"  {
	provisioner "local-exec" {
    	command = "echo  ${aws_instance.mytask-os1.public_ip} > publicip.txt"
 }
}

#Mounting EBS volume with var/www/html and copying the code from GitHub to the var/www/html:
resource "null_resource" "null_vol_attach"  {

	depends_on = [
    	aws_volume_attachment.mytask-attach1,
 ]


 	connection {
    	type     = "ssh"
    	user     = "ec2-user"
    	private_key = tls_private_key.mytask_p_key1.private_key_pem
    	host     = aws_instance.mytask-os1.public_ip
 }

	provisioner "remote-exec" {
    	inline = [
      	"sudo mkfs.ext4  /dev/xvdf",
      	"sudo mount  /dev/xvdf  /var/www/html",
      	"sudo rm -rf /var/www/html/*",
      	"sudo git clone https://github.com/aayushi0900/task1-.git /var/www/html/"
   ]
 }
}

#OUTPUT:
output "myos_ip" {
  	value = aws_instance.mytask-os1.public_ip
}

resource "null_resource" "null_vol_depend"  {

	depends_on = [
    	null_resource.null_vol_attach,
   ]
}

#Creating a S3 bucket to store the static data:
resource "aws_s3_bucket" "mytask-tera-bucket-0906" {
  	bucket = "mytask-tera-bucket0906"
  	acl    = "public-read"
  	force_destroy  = true
  	cors_rule {
    	allowed_headers = ["*"]
    	allowed_methods = ["PUT", "POST"]
    	allowed_origins = ["https://mytask-tera-bucket-0906"]
    	expose_headers  = ["ETag"]
    	max_age_seconds = 3000
 }
	depends_on = [
   	aws_volume_attachment.mytask-attach1,
  ]
}

#To upload data to S3 bucket:
resource "null_resource" "remove_and_upload_to_s3" {
  	provisioner "local-exec" {
    	command ="/home/aayushi/Desktop/tera/task1-/blob/master/index.html"
}	
	depends_on = [
   	aws_s3_bucket.mytask-tera-bucket-0906,
  ]
}

# Create Cloudfront distribution:
resource "aws_cloudfront_distribution" "mytask-distribution1" {
    	origin {
        domain_name = "${aws_s3_bucket.mytask-tera-bucket-0906.bucket_regional_domain_name}"
        origin_id = "S3-${aws_s3_bucket.mytask-tera-bucket-0906.bucket}"

        custom_origin_config {
            http_port = 80
            https_port = 443
            origin_protocol_policy = "match-viewer"
            origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        }
}
	# By default, show index.html file:
    	default_root_object = "index.html"
    	enabled = true

    	# If there is a 404, return index.html with a HTTP 200 Response:
    	custom_error_response {
        error_caching_min_ttl = 3000
        error_code = 404
        response_code = 200
        response_page_path = "/index.html"
    }

    	default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = "S3-${aws_s3_bucket.mytask-tera-bucket-0906.bucket}"

        #Not Forward all query strings, cookies and headers:
        forwarded_values {
            query_string = false
	    cookies {
		forward = "none"
	    }
            
        }

        viewer_protocol_policy = "redirect-to-https"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }

    	# Distributes content to all:
    	price_class = "PriceClass_All"

    	# Restricts who is able to access this content:
    	restrictions {
        geo_restriction {
        # type of restriction, blacklist, whitelist or none:
        restriction_type = "none"
        }
    }

    	# SSL certificate for the service:
    	viewer_certificate {
        cloudfront_default_certificate = true
    }
}

#OUTPUT:
output "cloudfront_ip_addr" {
  	value = aws_cloudfront_distribution.mytask-distribution1.domain_name
}

