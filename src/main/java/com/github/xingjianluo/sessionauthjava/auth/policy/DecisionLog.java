package com.github.xingjianluo.sessionauthjava.auth.policy;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 判定日志：记录每条判定依据的策略版本、关键输入与结论。
 * 容量有界（{@link #CAP}），写满后淘汰最旧记录，
 * 长期运行/高频判定下内存占用稳定、单条写入 O(1)。
 */
@Component
public class DecisionLog {

    /** 判定记录保留上限 */
    public static final int CAP = 1000;

    private final Deque<DecisionRecord> records = new ArrayDeque<>();
    private long seq = 0;

    /** 追加一条判定记录，返回记录（含分配的 ID） */
    public synchronized DecisionRecord record(String type, long policyVersion,
                                              Map<String, String> inputs, String outcome) {
        DecisionRecord record = new DecisionRecord(++seq, Instant.now(), type, policyVersion,
                Map.copyOf(inputs), outcome);
        records.addLast(record);
        while (records.size() > CAP) {
            records.pollFirst();
        }
        return record;
    }

    public synchronized Optional<DecisionRecord> find(long id) {
        for (DecisionRecord record : records) {
            if (record.id() == id) {
                return Optional.of(record);
            }
        }
        return Optional.empty();
    }

    /** 最近的若干条记录（新的在前） */
    public synchronized List<DecisionRecord> recent(int limit) {
        List<DecisionRecord> result = new ArrayList<>();
        var it = records.descendingIterator();
        while (it.hasNext() && result.size() < limit) {
            result.add(it.next());
        }
        return result;
    }

    public synchronized int size() {
        return records.size();
    }
}
