
# Vector-Based Semantic Search using Amazon OpenSearch Service

This is a blank project for Python development with CDK.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

This project is set up like a standard Python project.  The initialization
process also creates a virtualenv within this project, stored under the `.venv`
directory.  To create the virtualenv it assumes that there is a `python3`
(or `python` for Windows) executable in your path with access to the `venv`
package. If for any reason the automatic creation of the virtualenv fails,
you can create the virtualenv manually.

To manually create a virtualenv on MacOS and Linux:

```
$ python3 -m venv .venv
```

After the init process completes and the virtualenv is created, you can use the following
step to activate your virtualenv.

```
$ source .venv/bin/activate
```

If you are a Windows platform, you would activate the virtualenv like this:

```
% .venv\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
(.venv) $ pip install -r requirements.txt
```

At this point you can now synthesize the CloudFormation template for this code.

<pre>
(.venv) $ cdk synth \
              --parameters SageMakerNotebookInstanceType="<i>your-instance-type</i>" \
              --parameters OpenSearchDomainName="<i>your-opensearch-domain-name</i>" \
              --parameters EC2KeyPairName="<i>your-ec2-key-pair-name</i>"
</pre>

Use `cdk deploy` command to create the stack shown above.

<pre>
(.venv) $ cdk deploy \
              --parameters SageMakerNotebookInstanceType="<i>your-instance-type</i>" \
              --parameters OpenSearchDomainName="<i>your-opensearch-domain-name</i>" \
              --parameters EC2KeyPairName="<i>your-ec2-key-pair-name</i>"
</pre>

To add additional dependencies, for example other CDK libraries, just add
them to your `setup.py` file and rerun the `pip install -r requirements.txt`
command.

## Useful commands

 * `cdk ls`          list all stacks in the app
 * `cdk synth`       emits the synthesized CloudFormation template
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk docs`        open CDK documentation

Enjoy!

## References

 * [Text similarity search with vector fields](https://www.elastic.co/blog/text-similarity-search-with-vectors-in-elasticsearch)
 * [Vector-Based Semantic Search using Elasticsearch](https://medium.com/version-1/vector-based-semantic-search-using-elasticsearch-48d7167b38f5)
 * [Universal Sentence Encoder (TF2.0 Version 4)](https://tfhub.dev/google/universal-sentence-encoder/4)
 * [OpenSearch k-NN](https://opensearch.org/docs/latest/search-plugins/knn/index/)