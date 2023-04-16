pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh'''
                    docker build -t aug-ffm-auth .
                    docker tag aug-ffm-auth:latest 493270667162.dkr.ecr.ap-southeast-1.amazonaws.com/aug-ffm-auth:latest
                '''
            }
        }
        stage('Push') {
            steps {
                sh'''
                    aws ecr get-login-password --region ap-southeast-1 | docker login --username AWS --password-stdin 493270667162.dkr.ecr.ap-southeast-1.amazonaws.com
                    docker push 493270667162.dkr.ecr.ap-southeast-1.amazonaws.com/aug-ffm-auth:latest
                '''
            }
        }
    }
}