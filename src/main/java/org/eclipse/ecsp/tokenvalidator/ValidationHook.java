/********************************************************************************
 * Copyright (c) 2023-24 Harman International
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.tokenvalidator;

import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import java.util.List;

/**
 * A composable post-validation extension point invoked after standard claims validation.
 *
 * <p>Multiple hooks may be registered via {@code TokenValidatorBuilder.customValidators()};
 * they execute in ascending {@link #getOrder()} value. The {@code TokenValidator} interface
 * is not modified — hooks are a {@code DefaultTokenValidator} implementation concern.
 *
 * <p>This interface carries no Spring Framework dependency; {@link #getOrder()} is declared
 * directly so implementors need not add Spring to their compile classpath.
 *
 * @author Abhishek Kumar
 */
public interface ValidationHook {

    /**
     * Runs custom validation on the fully-verified, standard-validated claims.
     *
     * @param claims the verified claims returned by the standard pipeline
     * @throws InvalidClaimException if the custom validation constraint is not satisfied
     */
    void validate(List<TokenClaim> claims) throws InvalidClaimException;

    /**
     * Returns the execution order for this hook relative to other registered hooks.
     * Hooks execute in ascending order value (lower values execute first).
     *
     * @return the order value; default is 0
     */
    default int getOrder() {
        return 0;
    }
}
