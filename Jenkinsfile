pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh'''
                    echo "Building docker image..."
                    docker build -t auth-service:v1 .
                    docker tag auth-service:v1 shahedmehbub/jenkins-auth-service:v$BUILD_NUMBER
                '''
            }
        }

        stage('Push') {
            steps {
                sh'''
                    echo "Pushing docker image to dockerhub..."
                    docker push shahedmehbub/jenkins-auth-service:v$BUILD_NUMBER
                '''
            }
        }
    }
}