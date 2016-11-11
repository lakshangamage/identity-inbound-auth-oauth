/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.handler;

import com.nimbusds.jwt.JWT;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import org.wso2.carbon.identity.core.handler.MessageHandlerComparator;
import org.wso2.carbon.identity.framework.authentication.context.AuthenticationContext;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2InternalException;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oidc.internal.OIDCServiceComponentHolder;

import java.util.Collections;
import java.util.List;

public class OIDCHandlerManager {

    private static volatile OIDCHandlerManager instance = new OIDCHandlerManager();

    private OIDCHandlerManager() {

    }

    public static OIDCHandlerManager getInstance() {
        return instance;
    }

    public JWT buildIDToken(AuthenticationContext messageContext) throws OAuth2InternalException {

        List<IDTokenHandler> handlers = OIDCServiceComponentHolder.getInstance().getIDTokenHandlers();
        Collections.sort(handlers, new MessageHandlerComparator(messageContext));
        for(IDTokenHandler handler:handlers){
            if(handler.canHandle(messageContext)){
                return handler.buildIDToken(messageContext);
            }
        }
        throw OAuth2RuntimeException.error("Cannot find IntrospectionHandler to handle this request");
    }
}
