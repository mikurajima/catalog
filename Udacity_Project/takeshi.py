#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import psycopg2


def project():
    db = psycopg2.connect("dbname=news")
    cur = db.cursor()

    # 1. What are the most popular three articles of all time?
    # Which articles have been accessed the most?
    # Present this information as a sorted list with the most popular article
    # at the top.
    # "Princess Shellfish Marries Prince Handsome" ? 1201 views
    # add new column "article_id" (string) at "log" table
    sql = "SELECT path,\
                COUNT(path) AS count FROM log GROUP BY path ORDER \
                                BY count DESC limit 4"
    cur.execute(sql)
    results = cur.fetchall()
    print("#################################################################")
    for result in results:
        path = result[0]
        count = result[1]
        slug = path.strip("/article/")
        slug = path[9:]
        sql = "SELECT lead FROM articles WHERE slug = '{}';".format(slug)
        cur.execute(sql)
        results = cur.fetchall()
        for result in results:
            lead = result[0]
            print("{} -- {} views\n".format(lead, count))

    # #2. Who are the most popular article authors of all time?
    # That is, when you sum up all of the articles each author has written,
    # which authors get the most page views?
    # Present this as a sorted list with the most popular author at the top.
    # Ursula La Multa ? 2304 views
    sql = "WITH tb2 AS \
                (WITH tb AS \
                (SELECT SUBSTRING(path, 10) AS slug, COUNT(path) AS count\
                FROM log\
                GROUP BY path\
                ORDER BY count DESC)\
                SELECT articles.author AS author_id,\
                                SUM(tb.count) AS page_views\
                FROM articles\
                JOIN tb\
                ON tb.slug = articles.slug\
                GROUP BY articles.author\
                ORDER BY page_views DESC)\
                SELECT name, page_views\
                FROM tb2\
                JOIN authors\
                ON tb2.author_id = authors.id\
                ;"
    cur.execute(sql)
    results = cur.fetchall()
    print("#################################################################")
    for result in results:
        name = result[0]
        page_view = result[1]
        print("{} -- {} views\n".format(result[0], result[1]))

# 3. On which days did more than 1% of requests lead to errors?
# The log table includes a column status
# that indicates the HTTP status code that the news site sent to the user's
# browser.
# (Refer to this lesson for more information about the idea of HTTP status code
# July 29, 2016 ? 2.5% errors
    print("#################################################################")
    sql = "WITH tb200 AS\
                (WITH tb AS\
                (SELECT date_trunc('day', time) AS date, status\
                FROM log)\
                SELECT date AS date_200, status AS status_200,\
                                COUNT(status) AS count_200\
                FROM tb\
                WHERE status = '200 OK'\
                GROUP BY date, status\
                ORDER BY date),\
                tb404 AS(\
                WITH tb AS\
                (SELECT date_trunc('day', time) AS date, status\
                FROM log)\
                SELECT date AS date_404, status AS status_404,\
                                COUNT(status) AS count_404\
                FROM tb\
                WHERE status = '404 NOT FOUND'\
                GROUP BY date, status\
                ORDER BY date)\
                SELECT tb200.date_200, tb404.count_404, tb200.count_200,\
                                (tb404.count_404 * 1.0 / (tb404.count_404 *\
                                1.0 + tb200.count_200 * 1.0)) AS ratio2\
                FROM tb404\
                JOIN tb200\
                ON tb404.date_404 = tb200.date_200\
                GROUP BY tb200.date_200, tb404.count_404, tb200.count_200\
                ORDER BY tb200.date_200;"

    cur.execute(sql)
    results = cur.fetchall()
    for result in results:
        if result[3] >= 0.01:
            timestamp = result[0]
            date = timestamp.strftime('%Y/%m/%d')
            ratio = result[3] * 100
            ratio = round(ratio, 2)
            print("{} -- {}% errors".format(date[:10], ratio))
    return


if __name__ == '__main__':
    project()
