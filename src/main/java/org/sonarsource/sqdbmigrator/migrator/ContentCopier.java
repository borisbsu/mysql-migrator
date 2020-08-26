/*
 * SonarQube MySQL Database Migrator
 * Copyright (C) 2019-2019 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonarsource.sqdbmigrator.migrator;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonarsource.sqdbmigrator.migrator.Migrator.MigrationException;

public class ContentCopier {

  private static final Logger LOG = LoggerFactory.getLogger(ContentCopier.class);

  private static final int DEFAULT_BATCH_SIZE = 5000;
  private static final String CODESCAN_TABLE_PREFIX = "cs_";
  private static final String CODESCAN_ENCCONFIG_COLUMN = "encconfig";

  private ConnectionConfig sourceConfig;
  private ConnectionConfig targetConfig;

  public ContentCopier() {
  }

  public ContentCopier(ConnectionConfig sourceConfig, ConnectionConfig targetConfig) {
    this.sourceConfig = sourceConfig;
    this.targetConfig = targetConfig;
  }

  void execute(Database source, Database target, TableListProvider tableListProvider, StatsRecorder statsRecorder) {
    execute(source, target, tableListProvider, statsRecorder, DEFAULT_BATCH_SIZE);
  }

  void execute(Database source, Database target, TableListProvider tableListProvider, StatsRecorder statsRecorder, int batchSize) {
    tableListProvider.get(source).forEach(tableName -> {
      LOG.info("copying table {} ...", tableName);

      try {
        long started = new Date().getTime();

        target.truncateTable(tableName);

        boolean tableHasIdColumn = !tableName.startsWith(CODESCAN_TABLE_PREFIX) && source.tableHasIdColumn(tableName);

        if (tableHasIdColumn) {
          target.setIdentityInsert(tableName, true);
        }

        copyTable(source, target, tableName, batchSize);

        if (tableHasIdColumn) {
          target.setIdentityInsert(tableName, false);
          resetSequence(target, tableName);
        }

        long recordsCopied = ensureRowCountsMatch(source, target, tableName);

        statsRecorder.add(tableName, recordsCopied, started, new Date().getTime());
      } catch (SQLException e) {
        throw new MigrationException("Error while copying rows of table '%s': %s", tableName, e.getMessage());
      }
    });
  }

  private void copyTable(Database source, Database target, String tableName, int batchSize) throws SQLException {
    List<String> columnNames = source.getColumnNames(tableName).stream().map(String::toLowerCase).collect(Collectors.toList());

    String columnNamesSelect = columnNames.stream().map(col -> {
      if (tableName.startsWith(CODESCAN_TABLE_PREFIX) && col.equalsIgnoreCase(CODESCAN_ENCCONFIG_COLUMN)
              && ContentCopier.this.sourceConfig != null) {
        return "AES_DECRYPT(" + col + ", '" + ContentCopier.this.sourceConfig.encKey + "')";
      }
      return col;
    }).collect(Collectors.joining(","));
    String selectSql = String.format("select %s from %s", columnNamesSelect, tableName);

    int encConfigPos = tableName.startsWith(CODESCAN_TABLE_PREFIX) ? columnNames.indexOf(CODESCAN_ENCCONFIG_COLUMN) : -1;
    int columnCount = columnNames.size();
    String columnNamesCsv = String.join(", ", columnNames);
    String insertSql = String.format("insert into %s (%s) values (%s)", tableName, columnNamesCsv, formatPlaceholders(columnCount, encConfigPos));

    try (Statement statement = createStatement(source);
         ResultSet rs = statement.executeQuery(selectSql)) {
      int count = 0;
      try (PreparedStatement insertStatement = target.getConnection().prepareStatement(insertSql)) {
        while (rs.next()) {
          copyColumns(rs, insertStatement, encConfigPos);
          insertStatement.addBatch();

          count++;
          if (count % batchSize == 0) {
            insertStatement.executeBatch();
            target.getConnection().commit();
            count = 0;
          }
        }

        if (count > 0) {
          insertStatement.executeBatch();
          target.getConnection().commit();
        }
      }
    }
  }

  private static Statement createStatement(Database source) throws SQLException {
    Statement statement = source.getConnection().createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
    statement.setFetchSize(source.getFetchSize());
    return statement;
  }

  private void copyColumns(ResultSet rs, PreparedStatement insertStatement, int encConfigPos) throws SQLException {
    ResultSetMetaData rsMetaData = rs.getMetaData();
    int columnCount = rsMetaData.getColumnCount();
    for (int index = 1; index <= columnCount; index++) {
      if (rsMetaData.getColumnType(index) == Types.LONGVARBINARY) {
        if (encConfigPos > -1) {
          if (index == encConfigPos + 1) {
            insertStatement.setObject(index, rs.getObject(index));
            insertStatement.setObject(index + 1, ContentCopier.this.targetConfig.encKey);
          } else {
            insertStatement.setBytes(index > encConfigPos ? index + 1 : index, rs.getBytes(index));
          }
        } else {
          // special treatment for MySQL:longblob -> SqlServer:varbinary
          insertStatement.setBytes(index, rs.getBytes(index));
        }
      } else {
        if (encConfigPos > -1) {
          if (index == encConfigPos + 1) {
            insertStatement.setObject(index, rs.getObject(index));
            insertStatement.setObject(index + 1, ContentCopier.this.targetConfig.encKey);
          } else {
            insertStatement.setObject(index > encConfigPos ? index + 1 : index, rs.getObject(index));
          }
        } else {
          insertStatement.setObject(index, rs.getObject(index));
        }
      }
    }
  }

  private static String formatPlaceholders(int count, int encConfigPos) {
    StringBuilder sb = new StringBuilder(count * 2 - 1);
    IntStream.range(0, count).forEach(i -> {
      if (i > 0) {
        sb.append(",");
      }
      if (i == encConfigPos) {
        sb.append("ENCRYPT(?, ?, 'aes')");
      } else {
        sb.append("?");
      }
    });
    return sb.toString();
  }

  private static void resetSequence(Database database, String tableName) {
    try {
      long maxIdPlusOne = 1 + database.selectMaxId(tableName);
      database.resetSequence(tableName, maxIdPlusOne);
    } catch (SQLException e) {
      throw new MigrationException("Could not reset sequence for table %s: %s", tableName, e.getMessage());
    }
  }

  private static long ensureRowCountsMatch(Database source, Database target, String tableName) throws SQLException {
    long rowCountInSource = source.countRows(tableName);
    long rowCountInTarget = target.countRows(tableName);
    if (rowCountInSource != rowCountInTarget) {
      throw new MigrationException("Row counts don't match in source and target: %s != %s",
        tableName, rowCountInSource, rowCountInTarget);
    }
    return rowCountInTarget;
  }
}
