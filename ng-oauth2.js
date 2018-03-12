(function () {
    angular.module('ngOAuth2', []);
    /**
     * OAuth2 Service
     */
    angular.module('ngOAuth2')
        .provider('$oauth2', [
            '$httpProvider',
            function ($httpProvider) {
                var oauthConfig = {
                    authUrl: 'http://localhost', // 인증서버URL
                    grantType: 'password', // 인증유형
                    clientId: null, // 클라이언트 아이디
                    clientSecret: null, // 클라이언트 시크릿
                    tokenUri: '/oauth/token', // 토큰발급 URI
                    revokeUri: '/oauth/revoke' // 토큰파기 URI
                };
                // 설정을 Object 방식으로 한다
                this.setConfig = function (config) {
                    oauthConfig = angular.extend({
                        authUrl: 'http://localhost',
                        grantType: 'password',
                        clientId: null,
                        clientSecret: null,
                        tokenUri: '/oauth/token',
                        revokeUri: '/oauth/revoke'
                    }, config || {});
                };
                // 인증서버 URL을 설정한다
                this.setAuthorizationUrl = function (url) {
                    oauthConfig.authUrl = url || 'http://localhost';
                };
                // 인증유형을 설정한다
                this.setGrantType = function (grantType) {
                    oauthConfig.grantType = grantType || 'password';
                };
                // 클라이언트 아이디를 설정한다
                this.setClientId = function (clientId) {
                    oauthConfig.clientId = clientId || null;
                };
                // 클라이언트 시크릿을 설정한다
                this.setClientSecret = function (clientSecret) {
                    oauthConfig.clientSecret = clientSecret || null;
                };
                // 토큰 URI를 설정한다
                this.setTokenUri = function (uri) {
                    oauthConfig.tokenUri = uri || '/oauth/token';
                };
                // 토큰파기 URI를 설정한다
                this.setRevokeUri = function (uri) {
                    oauthConfig.revokeUri = uri || '/oauth/revoke';
                };
                $httpProvider.interceptors.push([
                    '$q',
                    function ($q) {
                        return {
                            'request': function (config) {
                                var storageName = btoa('Canabis.OAuth2.' + oauthConfig.clientId);
                                try {
                                    var token = JSON.parse(sessionStorage.getItem(storageName) || "{}");
                                    if (token && token.access_token && !config['headers']['Authorization']) {
                                        config['headers']['Authorization'] = [
                                            token.token_type,
                                            token.access_token
                                        ].join(' ');
                                    }
                                } catch (e) {
                                    __debug_error(e);
                                }
                                return config;
                            },
                            'requestError': function (config) {
                                return $q.reject(config);
                            },
                            'response': function (response) {
                                return response;
                            },
                            'responseError': function (response) {
                                return $q.reject(response);
                            }
                        };
                    }
                ]);
                /**
                 * 서비스 구현
                 */
                this.$get = [
                    '$rootScope',
                    '$http',
                    '$interval',
                    '$q',
                    '$timeout',
                    function ($rootScope, $http, $interval, $q, $timeout) {
                        var self = this;
                        var listener = null;
                        var onLoading = false;
                        var storageName = btoa('Canabis.OAuth2.' + oauthConfig.clientId);
                        /**
                         * 발급된 접근토큰을 받아온다
                         */
                        this.get = function () {
                            var token = null;
                            try {
                                token = JSON.parse(sessionStorage.getItem(storageName));
                                __debug_log('[OAuth2] 스토리지에서 접근토큰을 찾고 있습니다.', token);
                            } catch (e) {
                                // TODO::NOTHING
                            }
                            return token;
                        };
                        /**
                         * 접근토큰을 발급받는다
                         */
                        this.request = function () {
                            __debug_info('[OAuth2] 스토리지에 토큰정보가 있는지 찾아보고 있습니다...');
                            try {
                                var token = JSON.parse(localStroage.getItem(storageName));
                                if (null != token && token.refresh_token) {
                                    __debug_info('[OAuth2] 스토리지에 있는 토큰정보를 찾았습니다...', token);
                                    return __refresh();
                                } else {
                                    __debug_info('[OAuth2] 스토리지에서 토큰을 찾지못하였습니다...');
                                    __cleanup(true);

                                    switch (oauthConfig.grantType) {
                                    case 'password': // 패스워드 방식
                                        // Username, Password, Remember
                                        return __password(arguments[0], arguments[1], arguments[2]);
                                    default: // 기타 방식을 사용한 경우
                                        __FailureHandler();
                                        throw '[OAuth2] 지원하지 않는 인증유형입니다.';
                                    }
                                }
                            } catch (e) {
                                __debug_info('[OAuth2] 스토리지에서 토큰을 찾지못하였습니다...');
                                __cleanup(true);

                                switch (oauthConfig.grantType) {
                                case 'password': // 패스워드 방식
                                    // Username, Password, Remember
                                    return __password(arguments[0], arguments[1], arguments[2]);
                                default: // 기타 방식을 사용한 경우
                                    throw '[OAuth2] 지원하지 않는 인증유형입니다.';
                                }
                            }
                        };
                        /**
                         * 접근토큰을 파기한다
                         */
                        this.revoke = function () {
                            var deferred = $q.defer();
                            $http.get(__url_join(oauthConfig.authUrl, oauthConfig.revokeUri))
                                .then(function (e) {
                                    __cleanup();
                                    return deferred.resolve(e);
                                }, function (e) {
                                    __cleanup();
                                    return deferred.resolve(e);
                                });
                            return deferred.promise;
                        };
                        /**
                         * 접근토큰을 갱신한다
                         */
                        this.refresh = function () {
                            var deferred = $q.defer();
                            var token = null;
                            try {
                                token = JSON.parse(sessionStorage.getItem(storageName));
                                if (null != token && token.refresh_token) {
                                    var body = ['grant_type=refresh_token', 'refresh_token=' + token.refresh_token].join('&');
                                    $http({
                                        url: __url_join(oauthConfig.authUrl, oauthConfig.tokenUri),
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/x-www-form-urlencoded',
                                            'Authorization': __get_authorization()
                                        },
                                        data: body,
                                        withCredential: true
                                    }).then(function (e) {
                                        __debug_log('[OAuth2] 토큰이 갱신되었습니다.', e.data);
                                        __ResultHandler(e, token.remember);
                                        return deferred.resolve(e);
                                    }, function (e) {
                                        __debug_error('[OAuth2] 토큰갱신에 실패하였습니다.', e);
                                        __cleanup();
                                        __FailureHandler();
                                        return deferred.reject(e);
                                    });
                                } else {
                                    __FailureHandler();
                                    deferred.reject();
                                }
                            } catch (e) {
                                // FAILED TO PARSE TOKEN
                                __FailureHandler();
                                deferred.reject();
                            }
                            return deferred.promise;
                        };
                        /**
                         * 현재 상태를 가져온다
                         * @Result    {boolean}    true: 정지상태, false: 로딩 중
                         */
                        this.status = function () {
                            return !onLoading;
                        };
                        // 토큰을 모두 삭제한다
                        function __cleanup(slience) {
                            !slience ? __debug_info('[OAuth2] 리스너를 정지하고 있습니다...') : 0;
                            __safe_execute(listener);

                            !slience ? __debug_info('[OAuth2] 브라우저 스토리지에서 토큰정보를 삭제합니다...') : 0;
                            __stg_pop();
                        }
                        // 스토리지에 저장한다
                        function __stg_push(data, remember) {
                            sessionStorage.setItem(storageName, JSON.stringify(data));
                            if (remember == true) {
                                localStroage.setItem(storageName, JSON.stringify(data));
                            }
                        }
                        // 스토리지에서 삭제한다
                        function __stg_pop() {
                            sessionStorage.removeItem(storageName);
                            localStorage.removeItem(storageName);
                        }
                        // Client ID 및 Secret을 인코딩해준다
                        function __get_authorization() {
                            return 'Basic ' + btoa([oauthConfig.clientId, oauthConfig.clientSecret].join(':'));
                        }
                        // ResultHandler
                        function __ResultHandler(e, remember) {
                            var data = angular.extend(e.data, {
                                remember: remember
                            });
                            if (typeof data.expires_in == 'number' && data.expires_in > 0) {
                                __debug_info('[OAuth2] 리스너를 실행 중입니다...');
                                // listener = $timeout(function () {
                                //     self.refresh();
                                // }, data.expires_in - 10);
                            }
                            __stg_push(data, remember);
                            $rootScope.$broadcast('$oauth2.success', e);
                        }
                        // Failure Handler
                        function __FailureHandler(e) {
                            $rootScope.$broadcast('$oauth2.failed', e);
                        }
                        /**
                         * @Description: Password 방식
                         * @Param    {string}    username    사용자 아이디
                         * @Param    {string}    password    사용자 비밀번호
                         * @Param    {boolean}   remember    로그인 저장 여부
                         */
                        function __password(username, password, remember) {
                            var deferred = $q.defer();
                            var body = ['grant_type=password', 'username=' + username, 'password=' + password].join('&');
                            $http({
                                method: 'POST',
                                url: __url_join(oauthConfig.authUrl, oauthConfig.tokenUri),
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                    'Authorization': __get_authorization()
                                },
                                data: body
                            }).then(function (e) {
                                __debug_info('[OAuth2] 접큰토큰이 발급되었습니다.', e.data);
                                __ResultHandler(e, remember);
                                return deferred.resolve(e);
                            }, function (e) {
                                __debug_error('[OAuth2] 접근토큰을 발급받는데 실패하였습니다', e);
                                __FailureHandler();
                                __cleanup();
                                return deferred.reject(e);
                            });
                            return deferred.promise;
                        }
                        return this;
                    }
                ];
            }
        ]);
    /**
     * Data Transaction Service
     */
    angular.module('ngOAuth2')
        .provider('$data', [
            function () {
                var resourceUrl = 'http://localhost';
                this.setResourceUrl = function (url) {
                    resourceUrl = url || 'http://localhost';
                };
                /**
                 * 서비스 구현
                 */
                this.$get = [
                    '$http',
                    '$q',
                    '$oauth2',
                    '$rootScope',
                    function ($http, $q, $oauth2, $rootScope) {
                        var self = this;
                        this.get = function (url, config) {
                            var deferred = $q.defer();
                            __check_valid(url)
                                .then(function (e) {
                                    $http.get(__url_join(resourceUrl, url), config)
                                        .then(function (response) {
                                            return deferred.resolve(response);
                                        }, function (reject) {
                                            return deferred.reject(reject);
                                        });
                                }, function (e) {
                                    if ($oauth2.status()) {
                                        $oauth2.refresh()
                                            .then(function (e) {
                                                $http.get(__url_join(resourceUrl, url), config)
                                                    .then(function (e) {
                                                        return deferred.resolve(e);
                                                    }, function (e) {
                                                        return deferred.reject(e);
                                                    });
                                            }, function (e) {
                                                return deferred.reject(e);
                                            });
                                    } else {
                                        $rootScope.$on('$oauth2.success', function () {
                                            $http.get(__url_join(resourceUrl, url), config)
                                                .then(function (e) {
                                                    return deferred.resolve(e);
                                                }, function (e) {
                                                    return deferred.reject(e);
                                                });
                                        });
                                        $rootScope.$on('$oauth2.failed', function (e, args) {
                                            deferred.reject(args);
                                        });
                                    }
                                });
                            return deferred.promise;
                        };
                        this.delete = function (url, config) {
                            var deferred = $q.defer();
                            __check_valid(url)
                                .then(function (e) {
                                    $http.delete(__url_join(resourceUrl, url), config)
                                        .then(function (response) {
                                            return deferred.resolve(response);
                                        }, function (reject) {
                                            return deferred.reject(reject);
                                        });
                                }, function (e) {
                                    if ($oauth2.status()) {
                                        $oauth2.refresh()
                                            .then(function (e) {
                                                $http.delete(__url_join(resourceUrl, url), config)
                                                    .then(function (e) {
                                                        return deferred.resolve(e);
                                                    }, function (e) {
                                                        return deferred.reject(e);
                                                    });
                                            }, function (e) {
                                                return deferred.reject(e);
                                            });
                                    } else {
                                        $rootScope.$on('$oauth2.success', function () {
                                            $http.delete(__url_join(resourceUrl, url), config)
                                                .then(function (e) {
                                                    return deferred.resolve(e);
                                                }, function (e) {
                                                    return deferred.reject(e);
                                                });
                                        });
                                        $rootScope.$on('$oauth2.failed', function (e, args) {
                                            deferred.reject(args);
                                        });
                                    }
                                });
                            return deferred.promise;
                        };
                        this.post = function (url, data, config) {
                            var deferred = $q.defer();
                            __check_valid(url)
                                .then(function (e) {
                                    $http.post(__url_join(resourceUrl, url), data, config)
                                        .then(function (response) {
                                            return deferred.resolve(response);
                                        }, function (reject) {
                                            return deferred.reject(reject);
                                        });
                                }, function (e) {
                                    if ($oauth2.status()) {
                                        $oauth2.refresh()
                                            .then(function (e) {
                                                $http.post(__url_join(resourceUrl, url), data, config)
                                                    .then(function (e) {
                                                        return deferred.resolve(e);
                                                    }, function (e) {
                                                        return deferred.reject(e);
                                                    });
                                            }, function (e) {
                                                return deferred.reject(e);
                                            });
                                    } else {
                                        $rootScope.$on('$oauth2.success', function () {
                                            $http.post(__url_join(resourceUrl, url), data, config)
                                                .then(function (e) {
                                                    return deferred.resolve(e);
                                                }, function (e) {
                                                    return deferred.reject(e);
                                                });
                                        });
                                        $rootScope.$on('$oauth2.failed', function (e, args) {
                                            deferred.reject(args);
                                        });
                                    }
                                });
                            return deferred.promise;
                        };
                        this.put = function (url, data, config) {
                            var deferred = $q.defer();
                            __check_valid(url)
                                .then(function (e) {
                                    $http.put(__url_join(resourceUrl, url), data, config)
                                        .then(function (response) {
                                            return deferred.resolve(response);
                                        }, function (reject) {
                                            return deferred.reject(reject);
                                        });
                                }, function (e) {
                                    if ($oauth2.status()) {
                                        $oauth2.refresh()
                                            .then(function (e) {
                                                $http.put(__url_join(resourceUrl, url), data, config)
                                                    .then(function (e) {
                                                        return deferred.resolve(e);
                                                    }, function (e) {
                                                        return deferred.reject(e);
                                                    });
                                            }, function (e) {
                                                return deferred.reject(e);
                                            });
                                    } else {
                                        $rootScope.$on('$oauth2.success', function () {
                                            $http.put(__url_join(resourceUrl, url), data, config)
                                                .then(function (e) {
                                                    return deferred.resolve(e);
                                                }, function (e) {
                                                    return deferred.reject(e);
                                                });
                                        });
                                        $rootScope.$on('$oauth2.failed', function (e, args) {
                                            deferred.reject(args);
                                        });
                                    }
                                });
                            return deferred.promise;
                        };
                        /**
                         * 현재 토큰이 유효한지 확인
                         */
                        function __check_valid(url) {
                            var token = $oauth2.get();
                            var deferred = $q.defer();
                            if (token == null) {
                                // 로그인된 적이 없음
                                deferred.reject();
                            } else {
                                $http.head(__url_join(resourceUrl, url), {
                                    headers: {
                                        'Authorization': [token.token_type, token.access_token].join(' ')
                                    }
                                }).then(function (e) {
                                    return deferred.resolve(e);
                                }, function (e) {
                                    return deferred.reject(e);
                                });
                            }
                            return deferred.promise;
                        }
                        return this;
                    }
                ];
            }
        ]);
    /**
     * URL를 연결한다
     */
    function __url_join() {
        var urls = [];
        for (var i = 0; i < arguments.length; i++) {
            var url = String(arguments[i] || '').trim().replace(/^\/*|\/*$/g, '');
            url != '' ? urls.push(url) : 0;
        }
        return urls.join('/');
    }
    /**
     * DEBUG OPTIONS
     */
    var DEBUG = true;
    // 디버그 시, 로그를 출력한다
    function __debug_log() {
        if (DEBUG == true) {
            var args = ['DEBUG'];
            for (var i = 0; i < arguments.length; i++) {
                args.push(arguments[i]);
            }
            console.log.apply(null, args);
        }
    }
    // 디버그 시, 메시지를 출력한다
    function __debug_info() {
        if (DEBUG == true) {
            var args = ['DEBUG'];
            for (var i = 0; i < arguments.length; i++) {
                args.push(arguments[i]);
            }
            console.info.apply(null, args);
        }
    }
    // 디버그 시, 경고를 출력한다
    function __debug_warn() {
        if (DEBUG == true) {
            var args = ['DEBUG'];
            for (var i = 0; i < arguments.length; i++) {
                args.push(arguments[i]);
            }
            console.warn.apply(null, args);
        }
    }
    // 디버그 시, 에러를 출력한다
    function __debug_error() {
        if (DEBUG == true) {
            var args = ['DEBUG'];
            for (var i = 0; i < arguments.length; i++) {
                args.push(arguments[i]);
            }
            console.error.apply(null, args);
        }
    }
    /**
     * 함수 메소드를 안전하게 실행한다
     */
    function __safe_execute() {
        var func = arguments[0];
        var args = [];
        for (var i = 1; i < arguments.length; i++) {
            args.push(arguments[i]);
        }
        typeof func == 'function' ? func.apply(null, args) : 0;
    }
}());
