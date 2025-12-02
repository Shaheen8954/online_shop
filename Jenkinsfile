
@Library('Shared@main') _

pipeline {
    agent any
    
    options {
        skipStagesAfterUnstable()
    }

    environment {
        DockerHubUser = 'shaheen8954'
        DockerHubPassword = credentials('docker-hub-credentials')
        ImageTag = "${BUILD_NUMBER}"
        Url = ('https://github.com/Shaheen8954/online_shop.git')
        Branch = "feature"
        TRIVY_VERSION = '0.50.0'
    }

    stages {
        stage('Preflight - Skip') {
            steps {
                script {
                    def msgList = []
                    def authorList = []
                    def files = []
                    currentBuild.changeSets.each { cs ->
                        for (entry in cs.items) {
                            try { msgList << (entry.msg ?: '') } catch (ignored) { }
                            try { if (entry.author && entry.author.fullName) { authorList << entry.author.fullName } } catch (ignored) { }
                            try { entry.affectedFiles.each { f -> if (f?.path) { files << f.path } } } catch (ignored) { }
                        }
                    }
                    def msgs = msgList.join('\n')
                    def authors = authorList.unique()

                    if (msgs =~ /(?i)\[skip ci\]/) {
                        echo 'Skip: [skip ci]'
                        unstable('Preflight: [skip ci] present')
                        return
                    }

                    if (authors.any { it.equalsIgnoreCase('Jenkins CI') || it.endsWith('[bot]') }) {
                        echo "Skip: bot ${authors}"
                        unstable('Preflight: bot author commit')
                        return
                    }

                    def relevant = files.any { p ->
                        p == 'Jenkinsfile' || p == 'docker-compose.yml' ||
                        p.startsWith('backend/') || p.startsWith('frontend/')
                    }
                    if (!relevant) {
                        echo 'Skip: no relevant file changes'
                        unstable('Preflight: no relevant file changes')
                        return
                    }
                }
            }
        }

        stage('Cleanup Workspace') {
            steps {
                script {
                    cleanWs()
                }
            }
        }
        
        stage('Clone Repository') {
            steps {
                script {
                    clone(env.Url, env.Branch)
                }
            }
        }
       
        stage('Build Frontend Image') {
            steps {
                script {
                    dir('frontend') {
                        dockerbuild(env.DockerHubUser, online-shop2', env.ImageTag)
                    }
                }
            }
        }
        
        stage('Security Scans') {
            parallel {
                stage('File System Security Scan') {
                    steps {
                        script {
                            try {
                                // Install and run Gitleaks for secrets detection
                                sh '''
                                    wget -q -O gitleaks.tgz https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
                                    tar xf gitleaks.tgz gitleaks
                                    chmod +x gitleaks
                                    # Run gitleaks with our config file
                                    if [ -f .gitleaks.toml ]; then
                                        ./gitleaks detect --source . --report-format sarif --report-path gitleaks-report.json --config .gitleaks.toml || true
                                    else
                                        ./gitleaks detect --source . --report-format sarif --report-path gitleaks-report.json || true
                                    fi
                                    rm -f gitleaks.tgz gitleaks
                                '''
                                // Archive the report whether it found issues or not
                                archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                                
                                // Log findings, but do NOT fail or mark unstable
                                def findings = sh(script: 'if [ -s gitleaks-report.json ]; then echo "true"; else echo "false"; fi', returnStdout: true).trim()
                                if (findings == "true") {
                                    echo "Gitleaks: potential secrets found. Report archived at gitleaks-report.json."
                                } else {
                                    echo "Gitleaks: no findings."
                                }
                            } catch (Exception e) {
                                echo "Warning: File system security scan failed: ${e.message}"
                                // Continue the build even if the scan fails
                                currentBuild.result = 'STABLE'
                            }
                        }
                    }
                }
                
                stage('Trivy Image Scan') {
                    steps {
                        script {
                            try {
                                // Use Trivy Docker image for scanning
                                sh '''
                                    # Create reports directory
                                    mkdir -p trivy-reports
                                    
                                    # Function to scan image with Trivy Docker container
                                    scan_image() {
                                        local image_name=$1
                                        local report_name=$2
                                        
                                        echo "Scanning image: $image_name"
                                        docker run --rm \
                                            -v /var/run/docker.sock:/var/run/docker.sock \
                                            -v $(pwd)/trivy-reports:/reports \
                                            aquasec/trivy:${TRIVY_VERSION} image \
                                            --format json \
                                            -o /reports/${report_name} \
                                            ${image_name} || true
                                    }
                                    # Scan frontend image
                                    scan_image "${DockerHubUser}/online-shop2:${ImageTag}" "frontend-report.json"
                                '''
                                
                                // Archive the reports
                                archiveArtifacts artifacts: 'trivy-reports/*', allowEmptyArchive: true
                                
                            } catch (Exception e) {
                                echo "Warning: Trivy scan failed: ${e.message}"
                                // Continue the build even if the scan fails
                                currentBuild.result = 'STABLE'
                            }
                        }
                    }
                }
            }
        }
        
        stage('Push Docker Images') {
            when {
                allOf {
                    anyOf { branch 'main'; branch 'develop'; branch 'feature' }
                    // Only push if Docker login was successful
                    expression { currentBuild.result != 'FAILURE' }
                }
            }
            parallel {
                stage('Push Docker Image') {
                    steps {
                        script {
                            dockerpush(env.DockerHubUser, 'online-shop2', env.ImageTag)
                        }
                    }
                }
            }
        }
    }    
}        