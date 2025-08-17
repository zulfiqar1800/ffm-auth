pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh'''
                    echo "Building docker image..."
                    docker build -t auth-service:v1 .
                    docker tag auth-service:v1 rasheed1800/jenkins-auth-service:v$BUILD_NUMBER
                '''
            }
        }

        stage('Push') {
            steps {
                sh'''
                    echo "Pushing docker image to dockerhub..."
                    docker push rasheed1800/jenkins-auth-service:v$BUILD_NUMBER
                '''
            }
        }

        stage('Deploy') {
            steps {
                sh'''
                    echo "Deploying into swarm..."
                    ssh ubuntu@172.31.92.2 docker service update --image rasheed1800/jenkins-auth-service:v$BUILD_NUMBER ffm_auth
                '''
            }
        }
    }
}