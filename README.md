Вопрос 1: 
  Провести частичный анализ OVAL файла от компании RHEL(https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2) на первых 3 уязвимостях (патчах). Определить набор объектов, из которых онстроится. Понять основную логику "работы" данного формата.
Ответ: 
  основные объекты: <generator>
                    <definitions>(основные объекты):
                              definition:
                                    <title>
                                    <reference>
                                    <description>
                                    <issued>
                                    <updated>
                                    <cve>
                                    <criteria>
                                    
                    <tests>:
                              <red-def:rpminfo_test>
                              <red-def:object>
                              <red-def:state>
                    <objects> (основные):
                              <red-def:rpminfo_object>
                              <red-def:name>
                              <red-def:filepath>
                    <states>:
                              <red-def:rpminfo_state>
                                  <red-def:evr>
                                  <red-def:name>
                    <variables>
Вопрос 2:
  Описать текстом объекты, которые были найдены и для чего они используются. (Не более 2-3 фраз по каждому объекту).
Ответ:
  <generator> - информация о сгенерированном файле: название, версия, версия схемы, время генерации.\
  <definitions> - список уязвимостей (патчей) с описанием и проверками.
  <definition> - описание уязвимости (патча). Класс - уязвимость, патч. Id-уязвимости, версия уязвимости.
    <title> - название уязвимости
    <reference> - ссылки на сайт вендора и CVE (ссылки на уязвимость\патч)
    <description> - полное описание уязвимости
    <issued> - дата публикации
    <updated> - дата обновления
    <cve> - уровень критичности уязвимости (cvss3, ссылка на сайт вендора)
    <criteria> - содержит в себе условия для проверки наличия данной уязвимости. В данном объекте указан id теста, который проводится для проверки, и комментарий что делает данный тест.
    <tests> - содержит перечень тестов, необходимых для проверки. В каждом тесте указывается объект, для которого проводится проверка, обязательные условия и описание теста.
    <red-def:rpminfo_test> - в данном поле указывается id теста, проверка, описание теста и версия.
    <red-def:object> - id объекта, для которого проводится тест/проверка на соответствие
    <red-def:state> - id условий, которым необходимо соответствовать
    <objects> - содержит перечень объектов, для которых проводятся проверки
    <red-def:rpminfo_object> - версия, id объекта
    <red-def:name> - наименование объекта, пакета
    <red-def:filepath> - путь, где находится данный объект/пакет на АРМ
    <states> - перечень условий для выполнения тестов/проверок
    <red-def:rpminfo_state> - id условий, версия


Вопрос 4:
  Предложить и кратко описать свой вариант по упрощению формата для описания уязвимости вместе с проверками.
Ответ:
  Для упрощения восприятия информации из файла типа OVAL необходимо подцеплять сразу описание теста, объекта и условий. Поиск по файлу происходит через уникальный номер (id), который присвоен каждому тесту, объекту, условию. Данное изменение в формате убирает необходимость бегать в разные части файла для поиска информации, так как каждый пункт находится в своем отдельным "блоке". То есть мы получаем всю информацию о уязвимости/патче в одном месте и не тратим время и лишнии силы на поиск информации. Так же необходимо указать для каждого патча его название, время обновления, ссылки на источники, уровень критичности уязвимости.
Пример упрощенного формата (реализован в программе, код которой приложен):
{
        "class": "patch",
        "id": "oval:com.redhat.rhba:def:20191992",
        "title": "RHBA-2019:1992: cloud-init bug fix and enhancement update (Moderate)",
        "references": [
            {
                "ref_id": "RHBA-2019:1992",
                "ref_url": "https://access.redhat.com/errata/RHBA-2019:1992",
                "source": "RHSA"
            },
            {
                "ref_id": "CVE-2019-0816",
                "ref_url": "https://access.redhat.com/security/cve/CVE-2019-0816",
                "source": "CVE"
            }
        ],
        "description": "The cloud-init packages provide a set of init scripts for cloud instances. Cloud instances need special scripts to run during initialization to retrieve and install SSH keys, and to let the user run various scripts.\n\nUsers of cloud-init are advised to upgrade to these updated packages.",
        "updated_date": "2019-07-30",
        "cvss": "5.4/CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "criteria": {
            "operator": "OR",
            "elements": [
                {
                    "test_ref": "oval:com.redhat.rhba:tst:20191992005",
                    "details": {
                        "id": "oval:com.redhat.rhba:tst:20191992005",
                        "comment": "Red Hat Enterprise Linux must be installed",
                        "object_name": null,
                        "state_version": "635"
                    }
                },
                {
                    "operator": "AND",
                    "elements": [
                        {
                            "test_ref": "oval:com.redhat.rhba:tst:20191992001",
                            "details": {
                                "id": "oval:com.redhat.rhba:tst:20191992001",
                                "comment": "cloud-init is earlier than 0:18.5-1.el8.4",
                                "object_name": "cloud-init",
                                "state_version": "635"
                            }
                        },
                        {
                            "test_ref": "oval:com.redhat.rhba:tst:20191992002",
                            "details": {
                                "id": "oval:com.redhat.rhba:tst:20191992002",
                                "comment": "cloud-init is signed with Red Hat redhatrelease2 key",
                                "object_name": "cloud-init",
                                "state_version": "635"
                            }
                        },
                        {
                            "operator": "OR",
                            "elements": [
                                {
                                    "test_ref": "oval:com.redhat.rhba:tst:20191992003",
                                    "details": {
                                        "id": "oval:com.redhat.rhba:tst:20191992003",
                                        "comment": "Red Hat Enterprise Linux 8 is installed",
                                        "object_name": null,
                                        "state_version": "635"
                                    }
                                },
                                {
                                    "test_ref": "oval:com.redhat.rhba:tst:20191992004",
                                    "details": {
                                        "id": "oval:com.redhat.rhba:tst:20191992004",
                                        "comment": "Red Hat CoreOS 4 is installed",
                                        "object_name": null,
                                        "state_version": "635"
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    },
    {
