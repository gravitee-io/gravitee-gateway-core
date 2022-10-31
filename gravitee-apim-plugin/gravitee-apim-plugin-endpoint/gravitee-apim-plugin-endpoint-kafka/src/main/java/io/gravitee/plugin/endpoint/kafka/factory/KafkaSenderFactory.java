/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.plugin.endpoint.kafka.factory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import reactor.kafka.sender.KafkaSender;
import reactor.kafka.sender.SenderOptions;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class KafkaSenderFactory {

    public static final KafkaSenderFactory INSTANCE = new KafkaSenderFactory();
    private final Map<Integer, KafkaSender<?, ?>> senders = new ConcurrentHashMap<>();

    public <K, V> KafkaSender<K, V> createSender(final SenderOptions<K, V> senderOptions) {
        return (KafkaSender<K, V>) senders.computeIfAbsent(
            senderOptions.hashCode(),
            hashCode -> KafkaSender.create(CustomProducerFactory.INSTANCE, senderOptions)
        );
    }

    public void clear() {
        senders.forEach((integer, consumer) -> consumer.close());
        senders.clear();
    }
}
