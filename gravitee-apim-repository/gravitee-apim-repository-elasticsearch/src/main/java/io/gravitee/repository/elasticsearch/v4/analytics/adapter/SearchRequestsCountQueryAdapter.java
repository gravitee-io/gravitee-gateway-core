/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.repository.elasticsearch.v4.analytics.adapter;

import io.gravitee.repository.log.v4.model.analytics.RequestsCountQuery;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.util.ArrayList;
import java.util.HashMap;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SearchRequestsCountQueryAdapter {

    public static String adapt(RequestsCountQuery query) {
        var jsonContent = new HashMap<String, Object>();
        var esQuery = buildElasticQuery(query);
        if (esQuery != null) {
            jsonContent.put("query", esQuery);
        }
        jsonContent.put("aggs", buildEntrypointIdAggregate());
        return new JsonObject(jsonContent).encode();
    }

    private static JsonObject buildEntrypointIdAggregate() {
        return JsonObject.of("entrypoints", JsonObject.of("terms", JsonObject.of("field", "entrypoint-id")));
    }

    private static JsonObject buildElasticQuery(RequestsCountQuery query) {
        if (query == null) {
            return null;
        }

        var terms = new ArrayList<JsonObject>();
        if (query.getApiId() != null) {
            terms.add(JsonObject.of("term", JsonObject.of("api-id", query.getApiId())));
        }

        if (!terms.isEmpty()) {
            return JsonObject.of("bool", JsonObject.of("must", JsonArray.of(terms.toArray())));
        }

        return null;
    }
}
